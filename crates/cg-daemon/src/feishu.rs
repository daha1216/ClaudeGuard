//! Native durable Feishu / Lark webhook notifier for `cg-daemon`.
//!
//! Security & reliability properties:
//! - Webhook URL and optional signing secret are encrypted at rest with Windows DPAPI
//!   (`DpapiScope::LocalMachine`, so Session-0 `LocalSystem` service and admin CLI share access).
//! - Public [`FeishuStatus`] snapshots NEVER contain plaintext credentials — only presence flags
//!   and a masked webhook suffix.
//! - Outbound bodies are redacted via `cg_core::redact::redact` before enqueueing whenever
//!   `include_egress == false` (the privacy-safe default).
//! - Transient network/rate-limit failures are retained in a durable on-disk retry queue with
//!   exponential backoff (`15s -> 30s -> 60s -> 300s -> 900s`, up to 12 attempts).

use cg_platform::crypto_win::{
    feishu_webhook_sign, protect_str_base64, unprotect_str_base64, DpapiScope,
};
use cg_platform::probe_http::{post_json_notify, NetworkPolicy};
use cg_protocol::FeishuStatus;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_QUEUE: usize = 64;
const MAX_FAILED: usize = 64;
const MAX_ATTEMPTS: u32 = 12;
const FEISHU_PREFIX: &str = "https://open.feishu.cn/open-apis/bot/v2/hook/";
const LARK_PREFIX: &str = "https://open.larksuite.com/open-apis/bot/v2/hook/";
const LARKOFFICE_PREFIX: &str = "https://open.larkoffice.com/open-apis/bot/v2/hook/";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredFeishu {
    enabled: bool,
    webhook_enc: String,
    secret_enc: String,
    queue: VecDeque<QueuedEvent>,
    failed: VecDeque<FailedEvent>,
    last_sent_at: Option<u64>,
    last_error: String,
    next_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct QueuedEvent {
    id: u64,
    class: String,
    title: String,
    body: String,
    attempts: u32,
    next_attempt_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FailedEvent {
    event: QueuedEvent,
    error: String,
}

#[derive(Debug)]
struct DeliveryError {
    message: String,
    retryable: bool,
}

impl DeliveryError {
    fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Validates that a webhook URL targets an official Feishu or Lark custom bot endpoint.
pub fn validate_webhook_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    let token = trimmed
        .strip_prefix(FEISHU_PREFIX)
        .or_else(|| trimmed.strip_prefix(LARK_PREFIX))
        .or_else(|| trimmed.strip_prefix(LARKOFFICE_PREFIX))
        .ok_or_else(|| "请填写飞书 / Lark 群自定义机器人的官方 HTTPS Webhook 地址".to_string())?;
    if token.is_empty()
        || token.len() > 200
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Webhook 地址 Token 格式无效".into());
    }
    Ok(())
}

/// Returns a display-safe masked summary of a webhook URL without exposing the hook token.
pub fn mask_webhook_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Some(tok) = trimmed.strip_prefix(FEISHU_PREFIX) {
        let tail = tok.get(tok.len().saturating_sub(4)..).unwrap_or("");
        return format!("open.feishu.cn/.../{tail}");
    }
    if let Some(tok) = trimmed.strip_prefix(LARK_PREFIX) {
        let tail = tok.get(tok.len().saturating_sub(4)..).unwrap_or("");
        return format!("open.larksuite.com/.../{tail}");
    }
    if let Some(tok) = trimmed.strip_prefix(LARKOFFICE_PREFIX) {
        let tail = tok.get(tok.len().saturating_sub(4)..).unwrap_or("");
        return format!("open.larkoffice.com/.../{tail}");
    }
    String::new()
}

fn backoff_secs(attempts: u32) -> u64 {
    match attempts {
        0 | 1 => 15,
        2 => 30,
        3 => 60,
        4 => 180,
        5 => 300,
        _ => 900,
    }
}

fn classify_feishu_response(status: u16, body: &str) -> Result<(), DeliveryError> {
    if status == 429 || status >= 500 {
        return Err(DeliveryError::transient(format!(
            "飞书接口暂时繁忙（HTTP {status}），将自动退避重试"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(DeliveryError::permanent(format!(
            "飞书接口拒绝请求（HTTP {status}），请检查 Webhook 地址"
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| DeliveryError::transient("飞书响应不是有效 JSON，稍后重试"))?;
    let code = parsed
        .get("code")
        .and_then(|v| v.as_i64())
        .or_else(|| parsed.get("StatusCode").and_then(|v| v.as_i64()));
    match code {
        Some(0) => Ok(()),
        Some(99991400 | 5000) => Err(DeliveryError::transient(
            "飞书机器人触发限流或服务抖动，将稍后自动重试",
        )),
        Some(19021) => Err(DeliveryError::transient(
            "飞书拒绝消息（错误码 19021）：签名时间戳偏差过大，请校准系统时间",
        )),
        Some(19022) => Err(DeliveryError::permanent(
            "飞书拒绝消息（错误码 19022）：签名密钥 Secret 不匹配，请核对加签密钥",
        )),
        Some(19024) => Err(DeliveryError::permanent(
            "飞书拒绝消息（错误码 19024）：消息未包含自定义机器人安全关键词",
        )),
        Some(19025) => Err(DeliveryError::permanent(
            "飞书拒绝消息（错误码 19025）：当前出口 IP 不在飞书机器人 IP 白名单内",
        )),
        Some(n) => {
            let msg = parsed
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("请检查关键词、签名密钥或 IP 白名单");
            Err(DeliveryError::permanent(format!(
                "飞书拒绝消息（错误码 {n}）：{msg}"
            )))
        }
        None => Err(DeliveryError::transient("飞书回执缺少状态码，结果未确认")),
    }
}

fn build_feishu_payload(
    class: &str,
    title: &str,
    body: &str,
    event_id: u64,
    secret: &str,
    timestamp: i64,
) -> Result<serde_json::Value, String> {
    let template = match class {
        "trip" | "leak" | "antigravity_proxy" => "red",
        "warning" | "client_update" => "orange",
        "recover" | "test" => "green",
        _ => "blue",
    };
    let mut payload = json!({
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": { "tag": "plain_text", "content": title },
                "template": template,
            },
            "elements": [
                {
                    "tag": "markdown",
                    "content": format!("{body}\n\n<font color='grey'>ClaudeGuard · 事件 #{event_id}</font>")
                }
            ]
        }
    });
    if !secret.trim().is_empty() {
        let sign = feishu_webhook_sign(secret.trim(), timestamp.max(0) as u64);
        payload["timestamp"] = json!(timestamp.to_string());
        payload["sign"] = json!(sign);
    }
    Ok(payload)
}

fn encrypt_opt(plain: &str) -> Result<String, String> {
    let trimmed = plain.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    protect_str_base64(trimmed, DpapiScope::LocalMachine)
        .map_err(|e| format!("加密保存飞书凭据失败：{e}"))
}

fn decrypt_opt(enc: &str) -> String {
    let trimmed = enc.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    unprotect_str_base64(trimmed).unwrap_or_default()
}

/// Thread-safe, crash-resilient Feishu notifier owned by `EngineCoordinator`.
pub struct FeishuNotifier {
    path: PathBuf,
    state: Mutex<StoredFeishu>,
    flush_lock: Mutex<()>,
}

impl FeishuNotifier {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("feishu.json");
        let stored = fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<StoredFeishu>(&raw).ok())
            .unwrap_or_default();
        Self {
            path,
            state: Mutex::new(stored),
            flush_lock: Mutex::new(()),
        }
    }

    fn persist_locked(&self, st: &StoredFeishu) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建配置目录失败：{e}"))?;
        }
        let bytes =
            serde_json::to_vec_pretty(st).map_err(|e| format!("序列化飞书配置失败：{e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, &bytes).map_err(|e| format!("写入飞书配置临时文件失败：{e}"))?;
        fs::rename(&tmp, &self.path).map_err(|e| format!("原子落盘飞书配置失败：{e}"))?;
        Ok(())
    }

    /// Returns credential-free public status for [`cg_protocol::GuardSnapshot`].
    pub fn status(&self) -> FeishuStatus {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let plain_url = decrypt_opt(&st.webhook_enc);
        FeishuStatus {
            enabled: st.enabled,
            has_webhook: !st.webhook_enc.is_empty(),
            webhook_masked: mask_webhook_url(&plain_url),
            has_secret: !st.secret_enc.is_empty(),
            queued: st.queue.len(),
            failed: st.failed.len(),
            last_sent_at: st.last_sent_at,
            last_error: st.last_error.clone(),
        }
    }

    /// Encrypts and persists Feishu settings without exposing existing secrets.
    pub fn save_config(
        &self,
        enabled: bool,
        webhook: Option<String>,
        secret: Option<String>,
        clear_secret: bool,
    ) -> Result<FeishuStatus, String> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(raw_url) = webhook {
            let trimmed = raw_url.trim();
            if trimmed.is_empty() {
                // Keep existing webhook unless explicitly disabling with empty override?
                // Allow clearing only if user explicitly passed an empty string while disabling.
                if !enabled {
                    st.webhook_enc.clear();
                }
            } else {
                validate_webhook_url(trimmed)?;
                st.webhook_enc = encrypt_opt(trimmed)?;
            }
        }

        if clear_secret {
            st.secret_enc.clear();
        } else if let Some(raw_sec) = secret {
            let trimmed = raw_sec.trim();
            if !trimmed.is_empty() {
                st.secret_enc = encrypt_opt(trimmed)?;
            }
        }

        if enabled && st.webhook_enc.is_empty() {
            return Err("启用飞书通知前请先填写有效的飞书 Webhook HTTPS 地址".into());
        }

        st.enabled = enabled;
        st.last_error.clear();
        self.persist_locked(&st)?;

        let plain_url = decrypt_opt(&st.webhook_enc);
        Ok(FeishuStatus {
            enabled: st.enabled,
            has_webhook: !st.webhook_enc.is_empty(),
            webhook_masked: mask_webhook_url(&plain_url),
            has_secret: !st.secret_enc.is_empty(),
            queued: st.queue.len(),
            failed: st.failed.len(),
            last_sent_at: st.last_sent_at,
            last_error: st.last_error.clone(),
        })
    }

    /// Enqueues a notification event when Feishu is enabled & configured.
    pub fn enqueue(&self, class: &str, title: &str, body: &str) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !st.enabled || st.webhook_enc.is_empty() {
            return false;
        }
        let now = now_secs();
        st.next_id = st.next_id.max(now.saturating_mul(1000)) + 1;
        let id = st.next_id;
        if st.queue.len() >= MAX_QUEUE {
            if let Some(ev) = st.queue.pop_front() {
                if st.failed.len() >= MAX_FAILED {
                    st.failed.pop_front();
                }
                st.failed.push_back(FailedEvent {
                    event: ev,
                    error: "待发送队列已满，旧事件已转入失败记录".into(),
                });
            }
        }
        st.queue.push_back(QueuedEvent {
            id,
            class: class.to_string(),
            title: title.to_string(),
            body: body.to_string(),
            attempts: 0,
            next_attempt_at: now,
        });
        let _ = self.persist_locked(&st);
        true
    }

    /// Attempts to deliver all due queued events through `NetworkPolicy`.
    pub fn flush_due(&self, policy: &NetworkPolicy) -> usize {
        let Ok(_guard) = self.flush_lock.try_lock() else {
            return 0;
        };
        self.flush_due_with(|webhook, secret, ev| deliver_one(policy, webhook, secret, ev))
    }

    fn flush_due_with<F>(&self, deliver_fn: F) -> usize
    where
        F: Fn(&str, &str, &QueuedEvent) -> Result<(), DeliveryError>,
    {
        let mut delivered = 0usize;
        let mut tried_ids = Vec::with_capacity(8);

        for _ in 0..8 {
            let (ev, webhook, secret) = {
                let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !st.enabled || st.webhook_enc.is_empty() {
                    break;
                }
                let now = now_secs();
                let Some(due) = st
                    .queue
                    .iter()
                    .find(|item| item.next_attempt_at <= now && !tried_ids.contains(&item.id))
                else {
                    break;
                };
                let url = decrypt_opt(&st.webhook_enc);
                if url.is_empty() {
                    break;
                }
                let sec = decrypt_opt(&st.secret_enc);
                (due.clone(), url, sec)
            };

            tried_ids.push(ev.id);
            let send_res = deliver_fn(&webhook, &secret, &ev);
            let now = now_secs();
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(pos) = st.queue.iter().position(|item| item.id == ev.id) else {
                continue;
            };
            let Some(mut target) = st.queue.remove(pos) else {
                continue;
            };

            match send_res {
                Ok(()) => {
                    st.last_sent_at = Some(now);
                    st.last_error.clear();
                    delivered += 1;
                }
                Err(err) => {
                    st.last_error = err.message.clone();
                    target.attempts = target.attempts.saturating_add(1);
                    if err.retryable && target.attempts < MAX_ATTEMPTS {
                        target.next_attempt_at = now.saturating_add(backoff_secs(target.attempts));
                        st.queue.push_back(target);
                    } else {
                        if st.failed.len() >= MAX_FAILED {
                            st.failed.pop_front();
                        }
                        st.failed.push_back(FailedEvent {
                            event: target,
                            error: err.message,
                        });
                    }
                }
            }
            let _ = self.persist_locked(&st);
        }
        delivered
    }

    /// Immediately sends a redacted test card using either provided overrides or saved credentials.
    pub fn send_test(
        &self,
        policy: &NetworkPolicy,
        webhook_override: Option<&str>,
        secret_override: Option<&str>,
    ) -> Result<FeishuStatus, String> {
        let (webhook, secret, event_id) = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let url = match webhook_override.map(str::trim).filter(|s| !s.is_empty()) {
                Some(u) => {
                    validate_webhook_url(u)?;
                    u.to_string()
                }
                None => {
                    let saved = decrypt_opt(&st.webhook_enc);
                    if saved.is_empty() {
                        return Err("尚未保存飞书 Webhook 地址，请先填写或保存配置".into());
                    }
                    saved
                }
            };
            let sec = match secret_override.map(str::trim).filter(|s| !s.is_empty()) {
                Some(s) => s.to_string(),
                None => decrypt_opt(&st.secret_enc),
            };
            let now = now_secs();
            st.next_id = st.next_id.max(now.saturating_mul(1000)) + 1;
            (url, sec, st.next_id)
        };

        let ev = QueuedEvent {
            id: event_id,
            class: "test".into(),
            title: "ClaudeGuard 飞书通知测试".into(),
            body: "这是一条已脱敏的连通性测试消息（不包含任何出口 IP 或主机名）。如果你收到此卡片，说明飞书机器人加签与外发通道均工作正常。".into(),
            attempts: 1,
            next_attempt_at: now_secs(),
        };

        let res = deliver_one(policy, &webhook, &secret, &ev);
        let now = now_secs();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match res {
            Ok(()) => {
                st.last_sent_at = Some(now);
                st.last_error.clear();
                let _ = self.persist_locked(&st);
                let plain_url = decrypt_opt(&st.webhook_enc);
                Ok(FeishuStatus {
                    enabled: st.enabled,
                    has_webhook: !st.webhook_enc.is_empty(),
                    webhook_masked: mask_webhook_url(&plain_url),
                    has_secret: !st.secret_enc.is_empty(),
                    queued: st.queue.len(),
                    failed: st.failed.len(),
                    last_sent_at: st.last_sent_at,
                    last_error: String::new(),
                })
            }
            Err(err) => {
                st.last_error = err.message.clone();
                let _ = self.persist_locked(&st);
                Err(err.message)
            }
        }
    }
}

fn deliver_one(
    policy: &NetworkPolicy,
    webhook: &str,
    secret: &str,
    ev: &QueuedEvent,
) -> Result<(), DeliveryError> {
    let ts = now_secs() as i64;
    let payload = build_feishu_payload(&ev.class, &ev.title, &ev.body, ev.id, secret, ts)
        .map_err(DeliveryError::permanent)?;
    let (status, body) = post_json_notify(policy, webhook, &payload, Duration::from_secs(10))
        .map_err(|e| DeliveryError::transient(e.to_string()))?;
    classify_feishu_response(status, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validates_and_masks_feishu_and_lark_urls() {
        let feishu = "https://open.feishu.cn/open-apis/bot/v2/hook/abc12345-6789";
        let lark = "https://open.larksuite.com/open-apis/bot/v2/hook/xyz9988";
        let lark_office = "https://open.larkoffice.com/open-apis/bot/v2/hook/office4321";
        assert!(validate_webhook_url(feishu).is_ok());
        assert!(validate_webhook_url(lark).is_ok());
        assert!(validate_webhook_url(lark_office).is_ok());
        assert!(validate_webhook_url("http://open.feishu.cn/open-apis/bot/v2/hook/abc").is_err());
        assert!(validate_webhook_url("https://example.com/hook").is_err());
        assert_eq!(mask_webhook_url(feishu), "open.feishu.cn/.../6789");
        assert_eq!(mask_webhook_url(lark), "open.larksuite.com/.../9988");
        assert_eq!(
            mask_webhook_url(lark_office),
            "open.larkoffice.com/.../4321"
        );
    }

    #[test]
    fn classifies_business_and_http_responses() {
        assert!(classify_feishu_response(200, r#"{"code":0,"msg":"ok"}"#).is_ok());
        assert!(classify_feishu_response(200, r#"{"StatusCode":0}"#).is_ok());
        let rate = classify_feishu_response(200, r#"{"code":99991400}"#).unwrap_err();
        assert!(rate.retryable);
        let ts_skew = classify_feishu_response(200, r#"{"code":19021,"msg":"timestamp expired"}"#)
            .unwrap_err();
        assert!(ts_skew.retryable);
        assert!(ts_skew.message.contains("时间戳偏差"));
        let bad_sec =
            classify_feishu_response(200, r#"{"code":19022,"msg":"sign match fail"}"#).unwrap_err();
        assert!(!bad_sec.retryable);
        assert!(bad_sec.message.contains("Secret 不匹配"));
        let bad_kw = classify_feishu_response(200, r#"{"code":19024,"msg":"Key Words Not Found"}"#)
            .unwrap_err();
        assert!(!bad_kw.retryable);
        assert!(bad_kw.message.contains("安全关键词"));
        let bad_ip =
            classify_feishu_response(200, r#"{"code":19025,"msg":"ip not allowed"}"#).unwrap_err();
        assert!(!bad_ip.retryable);
        assert!(bad_ip.message.contains("IP 白名单"));
        let http502 = classify_feishu_response(502, "bad gateway").unwrap_err();
        assert!(http502.retryable);
    }

    #[test]
    fn flush_due_skips_backoff_head_of_line_and_prevents_concurrent_duplicate_sends() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempdir().unwrap();
        let notifier = Arc::new(FeishuNotifier::load(dir.path()));
        notifier
            .save_config(
                true,
                Some("https://open.larkoffice.com/open-apis/bot/v2/hook/token-abcd".into()),
                None,
                false,
            )
            .expect("save larkoffice config");

        assert!(notifier.enqueue("warning", "第一条待退避", "事件一"));
        assert!(notifier.enqueue("trip", "第二条紧急告警", "事件二"));

        // First flush: event #1 hits transient failure (enters backoff), event #2 still delivers immediately!
        let delivered = notifier.flush_due_with(|_url, _sec, ev| {
            if ev.title.contains("第一条") {
                Err(DeliveryError::transient("模拟网络抖动"))
            } else {
                Ok(())
            }
        });
        assert_eq!(delivered, 1, "event #2 must bypass backoff head-of-line");
        assert_eq!(notifier.status().queued, 1);

        // Enqueue event #3 and verify flush_lock prevents concurrent duplicate sends.
        assert!(notifier.enqueue("recover", "第三条恢复", "事件三"));
        let calls = Arc::new(AtomicUsize::new(0));
        let guard = notifier.flush_lock.lock().unwrap();
        assert_eq!(
            notifier.flush_due(&NetworkPolicy::direct()),
            0,
            "concurrent flush_due must immediately return 0 while flush_lock is held"
        );
        drop(guard);

        let calls_ref = calls.clone();
        let delivered2 = notifier.flush_due_with(|_url, _sec, _ev| {
            calls_ref.fetch_add(1, Ordering::AcqRel);
            Ok(())
        });
        assert_eq!(
            delivered2, 1,
            "due event #3 delivered while event #1 stays in backoff"
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(notifier.status().queued, 1);
    }

    #[test]
    fn dpapi_config_roundtrip_and_queue_persistence() {
        let dir = tempdir().unwrap();
        let notifier = FeishuNotifier::load(dir.path());
        let st = notifier
            .save_config(
                true,
                Some("https://open.feishu.cn/open-apis/bot/v2/hook/test-token-1234".into()),
                Some("my-secret-key".into()),
                false,
            )
            .expect("save feishu config");
        assert!(st.enabled);
        assert!(st.has_webhook);
        assert!(st.has_secret);
        assert_eq!(st.webhook_masked, "open.feishu.cn/.../1234");

        // On-disk JSON must never contain plaintext URL token or secret
        let disk = fs::read_to_string(dir.path().join("feishu.json")).unwrap();
        assert!(!disk.contains("test-token-1234"));
        assert!(!disk.contains("my-secret-key"));

        assert!(notifier.enqueue("trip", "熔断告警", "出口偏离已隔离"));
        let reloaded = FeishuNotifier::load(dir.path());
        let st2 = reloaded.status();
        assert!(st2.enabled);
        assert_eq!(st2.queued, 1);
        assert_eq!(st2.webhook_masked, "open.feishu.cn/.../1234");
    }
}
