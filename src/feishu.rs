//! Native Feishu notifications: user-scoped DPAPI secrets and a durable retry queue.
//! UI responses contain presence flags only, never decrypted credentials.
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Default, Clone, Deserialize, Serialize)]
#[serde(default)]
struct Stored {
    enabled: bool,
    webhook: String,
    secret: String,
    imported: bool,
    previous_ok: Option<bool>,
    previous_trip: bool,
    queue: VecDeque<Event>,
    failed: VecDeque<FailedEvent>,
    discarded: u64,
    last_sent: u64,
    error: String,
    next_id: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct Event {
    id: u64,
    text: String,
    attempts: u32,
    next: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct FailedEvent {
    event: Event,
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
}
impl From<String> for DeliveryError {
    fn from(message: String) -> Self {
        Self {
            message,
            retryable: true,
        }
    }
}
impl From<&str> for DeliveryError {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

fn business_result(code: Option<i64>) -> Result<(), DeliveryError> {
    match code {
        Some(0) => Ok(()),
        Some(99991400 | 5000) => Err("飞书暂时限流或服务异常，将稍后重试".into()),
        Some(n) => Err(DeliveryError::permanent(format!(
            "飞书拒绝消息（{n}），请检查 Webhook、关键词、签名和机器人 IP 白名单"
        ))),
        None => Err("飞书回执缺少成功状态，送达结果未确认".into()),
    }
}

fn retain_failed(data: &mut Stored, event: Event, error: String) {
    if data.failed.len() >= 100 {
        data.failed.pop_front();
        data.discarded += 1;
    }
    data.failed.push_back(FailedEvent { event, error });
}

fn enqueue(data: &mut Stored, message: &str) {
    data.next_id = data.next_id.max(now() * 1000) + 1;
    let id = data.next_id;
    if let Some(event) = (data.queue.len() >= 100)
        .then(|| data.queue.pop_front())
        .flatten()
    {
        retain_failed(data, event, "待发送队列已满，请手动补发此通知".into());
    }
    data.queue.push_back(Event {
        id,
        text: format!("ClaudeGuard · {message}\n事件：{id}"),
        attempts: 0,
        next: now(),
    });
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub enabled: bool,
    pub has_webhook: bool,
    pub has_secret: bool,
    pub imported: bool,
    pub queued: usize,
    pub last_sent: u64,
    pub error: String,
    pub failed: usize,
    pub last_failure: String,
    pub next_retry: u64,
    pub discarded: u64,
}

#[derive(Deserialize)]
pub struct Settings {
    pub enabled: bool,
    pub webhook: Option<String>,
    pub secret: Option<String>,
    pub clear_secret: bool,
}

pub struct Notifier {
    data: Mutex<Stored>,
    path: PathBuf,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_url(url: &str) -> Result<(), String> {
    let token = url
        .strip_prefix("https://open.feishu.cn/open-apis/bot/v2/hook/")
        .ok_or("请填写飞书群自定义机器人的 HTTPS Webhook 地址")?;
    if token.is_empty()
        || token.len() > 200
        || !token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return Err("Webhook 地址格式不正确".into());
    }
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct Blob {
    len: u32,
    data: *mut u8,
}

#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        input: *const Blob,
        description: *const u16,
        entropy: *const Blob,
        reserved: *mut std::ffi::c_void,
        prompt: *mut std::ffi::c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *const Blob,
        description: *mut *mut u16,
        entropy: *const Blob,
        reserved: *mut std::ffi::c_void,
        prompt: *mut std::ffi::c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
}
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(windows)]
fn crypt(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    if bytes.len() > 65_536 {
        return Err("凭据长度无效".into());
    }
    let input = Blob {
        len: bytes.len() as u32,
        data: bytes.as_ptr() as *mut u8,
    };
    let mut output = Blob {
        len: 0,
        data: std::ptr::null_mut(),
    };
    // DPAPI allocates output, which must be released with LocalFree on every successful path.
    unsafe {
        let ok = if decrypt {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("Windows 凭据加密或解密失败，请重新填写".into());
        }
        let result = if output.len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(output.data, output.len as usize).to_vec()
        };
        LocalFree(output.data.cast());
        Ok(result)
    }
}

#[cfg(target_os = "macos")]
fn crypt(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    crate::macos::credentials::crypt(bytes, decrypt)
}

fn encrypt(text: &str) -> Result<String, String> {
    Ok(STANDARD.encode(crypt(text.as_bytes(), false)?))
}
fn decrypt(text: &str) -> Result<String, String> {
    let data = STANDARD.decode(text).map_err(|_| "加密凭据格式错误")?;
    String::from_utf8(crypt(&data, true)?).map_err(|_| "凭据解密结果无效".into())
}

fn request_body(text: &str, secret: &str, timestamp: u64) -> serde_json::Value {
    let mut body = serde_json::json!({"msg_type":"text", "content":{"text":text}});
    if !secret.is_empty() {
        let key = format!("{timestamp}\n{secret}");
        let mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts arbitrary key lengths");
        body["timestamp"] = timestamp.to_string().into();
        body["sign"] = STANDARD.encode(mac.finalize().into_bytes()).into();
    }
    body
}

fn send(stored: &Stored, text: &str) -> Result<(), DeliveryError> {
    let url = decrypt(&stored.webhook).map_err(DeliveryError::permanent)?;
    validate_url(&url).map_err(DeliveryError::permanent)?;
    let secret = if stored.secret.is_empty() {
        String::new()
    } else {
        decrypt(&stored.secret).map_err(DeliveryError::permanent)?
    };
    // Do not inherit the monitored proxy; never redirect a credential-bearing request.
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .build();
    let body = request_body(text, &secret, now()).to_string();
    let response = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => DeliveryError {
                message: format!("飞书 HTTP {code}"),
                retryable: code == 408 || code == 429 || code >= 500,
            },
            _ => DeliveryError::from("连接飞书失败，送达结果未确认；将保留同一事件编号重试"),
        })?;
    let text = response.into_string().map_err(|_| "读取飞书响应失败")?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| "飞书响应格式无效")?;
    let code = value
        .get("code")
        .or_else(|| value.get("StatusCode"))
        .and_then(|v| v.as_i64());
    business_result(code)
}

impl Notifier {
    pub fn load() -> Self {
        let path = crate::config::config_dir().join("feishu.json");
        let data = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| Stored {
                error: "通知配置读取失败，请重新保存配置".into(),
                ..Stored::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::import_legacy(),
            Err(_) => Stored {
                error: "无法读取通知配置，请检查文件权限".into(),
                ..Stored::default()
            },
        };
        Self {
            data: Mutex::new(data),
            path,
        }
    }

    fn import_legacy() -> Stored {
        let legacy = crate::config::config_dir()
            .with_file_name("ClaudeGuardFeishu")
            .join("config.json");
        let parsed = std::fs::read_to_string(legacy)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
        let Some(value) = parsed else {
            return Stored::default();
        };
        let mut data = Stored {
            webhook: value["webhook"].as_str().unwrap_or_default().into(),
            secret: value["secret"].as_str().unwrap_or_default().into(),
            enabled: value["enabled"].as_bool().unwrap_or(false),
            ..Stored::default()
        };
        let valid = decrypt(&data.webhook)
            .and_then(|u| validate_url(&u))
            .and_then(|_| {
                if data.secret.is_empty() {
                    Ok(())
                } else {
                    decrypt(&data.secret).map(|_| ())
                }
            });
        if let Err(error) = valid {
            data.enabled = false;
            data.error = error;
        } else {
            data.imported = true;
        }
        data
    }

    fn persist(&self, data: &Stored) -> Result<(), String> {
        let dir = self.path.parent().ok_or("通知配置目录无效")?;
        std::fs::create_dir_all(dir).map_err(|_| "无法创建通知配置目录")?;
        let text = serde_json::to_vec_pretty(data).map_err(|_| "通知配置序列化失败")?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|_| "无法写入通知配置")?;
        std::fs::rename(tmp, &self.path).map_err(|_| "无法保存通知配置".into())
    }

    pub fn status(&self) -> Status {
        let data = self.data.lock().unwrap();
        Status {
            enabled: data.enabled,
            has_webhook: !data.webhook.is_empty(),
            has_secret: !data.secret.is_empty(),
            imported: data.imported,
            queued: data.queue.len(),
            last_sent: data.last_sent,
            error: data.error.clone(),
            failed: data.failed.len(),
            last_failure: data
                .failed
                .back()
                .map(|f| f.error.clone())
                .unwrap_or_default(),
            next_retry: data
                .queue
                .front()
                .filter(|e| e.attempts > 0)
                .map(|e| e.next)
                .unwrap_or(0),
            discarded: data.discarded,
        }
    }

    pub fn notify(&self, message: &str) {
        let mut data = self.data.lock().unwrap();
        if !data.enabled {
            return;
        }
        enqueue(&mut data, message);
        if let Err(error) = self.persist(&data) {
            data.error = error;
        }
    }

    pub fn configure(&self, settings: Settings) -> Result<Status, String> {
        let mut data = self.data.lock().unwrap();
        let mut next = data.clone();
        if let Some(url) = settings.webhook.filter(|s| !s.trim().is_empty()) {
            let url = url.trim();
            validate_url(url)?;
            // DPAPI is randomized: compare plaintext before replacing the ciphertext,
            // or saving the same endpoint would discard its outstanding notifications.
            if decrypt(&data.webhook)
                .map(|saved| saved != url)
                .unwrap_or(true)
            {
                next.webhook = encrypt(url)?;
            }
        }
        if settings.clear_secret {
            next.secret.clear();
        } else if let Some(secret) = settings.secret.filter(|s| !s.trim().is_empty()) {
            let secret = secret.trim();
            if decrypt(&data.secret)
                .map(|saved| saved != secret)
                .unwrap_or(true)
            {
                next.secret = encrypt(secret)?;
            }
        }
        if settings.enabled {
            validate_url(&decrypt(&next.webhook)?)?;
            if !next.secret.is_empty() {
                decrypt(&next.secret)?;
            }
        }
        if next.webhook != data.webhook || next.secret != data.secret || !settings.enabled {
            next.queue.clear();
        }
        if next.webhook != data.webhook {
            next.failed.clear();
            next.discarded = 0;
        }
        if settings.enabled && !data.enabled {
            // Re-enabling during an ongoing outage must still report that outage.
            next.previous_ok = None;
            next.previous_trip = false;
        }
        next.enabled = settings.enabled;
        next.error.clear();
        self.persist(&next)?;
        *data = next;
        drop(data);
        Ok(self.status())
    }

    pub fn test(&self) -> Result<Status, String> {
        let snapshot = self.data.lock().unwrap().clone();
        let result = send(&snapshot, "ClaudeGuard · 内置飞书通知测试\n连接成功。通知现已集成在 ClaudeGuard 内。\n这是一条测试消息，未触发实际熔断。");
        let mut data = self.data.lock().unwrap();
        match &result {
            Ok(()) => {
                data.last_sent = now();
                data.error.clear();
            }
            Err(e) => data.error = e.message.clone(),
        }
        self.persist(&data)?;
        drop(data);
        result.map_err(|e| e.message)?;
        Ok(self.status())
    }

    pub fn retry_failed(&self) -> Result<Status, String> {
        let mut data = self.data.lock().unwrap();
        if !data.enabled {
            return Err("请先启用飞书通知".into());
        }
        let mut next = data.clone();
        while next.queue.len() < 100 {
            let Some(failed) = next.failed.pop_front() else {
                break;
            };
            let mut event = failed.event;
            event.attempts = 0;
            event.next = now();
            next.queue.push_back(event);
        }
        next.error.clear();
        self.persist(&next)?;
        *data = next;
        drop(data);
        Ok(self.status())
    }

    pub fn observe(
        &self,
        passed: bool,
        reason: &str,
        ip: Option<&str>,
        tripped: bool,
        detail: &str,
    ) {
        let mut data = self.data.lock().unwrap();
        let kind = transition(data.previous_ok, data.previous_trip, passed, tripped);
        data.previous_ok = Some(passed);
        data.previous_trip = tripped;
        if data.enabled {
            if let Some(kind) = kind {
                let text = format!(
                    "{kind}通知\n出口：{}\n检查：{}\n处理状态：{detail}",
                    ip.unwrap_or("本次未获取"),
                    if passed { "已恢复正常" } else { reason }
                );
                enqueue(&mut data, &text);
            }
        }
        if let Err(e) = self.persist(&data) {
            data.error = e;
        }
    }

    pub fn start(self: &Arc<Self>, stop: Arc<std::sync::atomic::AtomicBool>) {
        let notifier = Arc::clone(self);
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                notifier.deliver_one();
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }

    fn deliver_one(&self) {
        self.deliver_with(send);
    }

    fn deliver_with(&self, send_request: impl FnOnce(&Stored, &str) -> Result<(), DeliveryError>) {
        let snapshot = self.data.lock().unwrap().clone();
        if !snapshot.enabled {
            return;
        }
        let Some(event) = snapshot.queue.front().filter(|e| e.next <= now()) else {
            return;
        };
        let age = now().saturating_sub(event.id / 1000);
        let text = if age >= 60 {
            format!(
                "{}\n延后发送：事件发生于约 {} 分钟前。",
                event.text,
                age / 60
            )
        } else {
            event.text.clone()
        };
        let result = send_request(&snapshot, &text);
        let mut data = self.data.lock().unwrap();
        // A settings change may clear this queue while the HTTP request is in flight.
        if data.queue.front().map(|e| e.id) != Some(event.id) {
            return;
        }
        match result {
            Ok(()) => {
                data.queue.pop_front();
                data.last_sent = now();
                data.error.clear();
            }
            Err(error) => {
                data.error = error.message.clone();
                if let Some(front) = data.queue.front_mut() {
                    front.attempts += 1;
                    front.next = now() + (15u64 * 2u64.pow(front.attempts.min(5))).min(300);
                    if !error.retryable || front.attempts >= 5 {
                        let event = data.queue.pop_front().unwrap();
                        data.error
                            .push_str("；已停止自动重试，失败通知已保留，可修正后手动补发");
                        let reason = data.error.clone();
                        retain_failed(&mut data, event, reason);
                    }
                }
            }
        }
        if let Err(error) = self.persist(&data) {
            data.error = error;
        }
    }
}

fn transition(
    previous: Option<bool>,
    was_tripped: bool,
    passed: bool,
    tripped: bool,
) -> Option<&'static str> {
    if passed {
        if previous == Some(false) {
            Some("恢复")
        } else {
            None
        }
    } else if previous != Some(false) {
        Some("异常")
    } else if tripped && !was_tripped {
        Some("熔断")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transitions_deduplicate_and_escalate() {
        assert_eq!(transition(None, false, true, false), None);
        assert_eq!(transition(None, false, false, false), Some("异常"));
        assert_eq!(transition(Some(false), false, false, false), None);
        assert_eq!(transition(Some(false), false, false, true), Some("熔断"));
        assert_eq!(transition(Some(false), true, false, true), None);
        assert_eq!(transition(Some(false), true, true, false), Some("恢复"));
    }
    #[test]
    fn rejected_notifications_are_retained_and_manual_retry_keeps_event_id() {
        let dir = std::env::temp_dir().join(format!(
            "cg-feishu-retain-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let notifier = Notifier {
            path: dir.join("feishu.json"),
            data: Mutex::new(Stored {
                enabled: true,
                ..Stored::default()
            }),
        };
        notifier.notify("test event");
        let original = notifier.data.lock().unwrap().queue[0].id;
        notifier.deliver_with(|_, _| Err(DeliveryError::permanent("signature rejected")));
        assert_eq!(notifier.status().queued, 0);
        assert_eq!(notifier.status().failed, 1);
        // Delivering another notification must not erase an earlier failure record.
        notifier.notify("later event");
        notifier.deliver_with(|_, _| Ok(()));
        assert_eq!(notifier.status().failed, 1);
        let saved: Stored =
            serde_json::from_str(&std::fs::read_to_string(&notifier.path).unwrap()).unwrap();
        assert_eq!(saved.failed[0].event.id, original);
        notifier.retry_failed().unwrap();
        assert_eq!(notifier.data.lock().unwrap().queue[0].id, original);
        notifier.deliver_with(|_, _| Ok(()));
        assert_eq!(notifier.status().failed, 0);
        std::fs::remove_file(&notifier.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn temporary_failures_stop_after_five_attempts_without_losing_the_event() {
        let dir = std::env::temp_dir().join(format!(
            "cg-feishu-exhaust-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let notifier = Notifier {
            path: dir.join("feishu.json"),
            data: Mutex::new(Stored {
                enabled: true,
                ..Stored::default()
            }),
        };
        notifier.notify("test event");
        for attempt in 1..=5 {
            notifier.data.lock().unwrap().queue[0].next = 0;
            notifier.deliver_with(|_, _| Err("network unavailable".into()));
            if attempt < 5 {
                assert_eq!(notifier.status().queued, 1);
            }
        }
        assert_eq!(notifier.status().queued, 0);
        assert_eq!(notifier.status().failed, 1);
        assert_eq!(notifier.data.lock().unwrap().failed[0].event.attempts, 5);
        assert!(!business_result(Some(19024)).unwrap_err().retryable);
        assert!(business_result(Some(99991400)).unwrap_err().retryable);
        assert!(business_result(Some(0)).is_ok());
        std::fs::remove_file(&notifier.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn signature_matches_independent_known_vector() {
        let body = request_body("test", "secret", 100);
        assert_eq!(body["timestamp"], "100");
        assert_eq!(body["sign"], "KUnJ8wrVSlQE2kFHpc7kL1u/Kp43Y+UBQpRojlmoDyo=");
        assert!(request_body("test", "", 100).get("sign").is_none());
    }
    #[test]
    fn webhook_cannot_redirect_credentials() {
        assert!(validate_url("https://open.feishu.cn/open-apis/bot/v2/hook/test-id").is_ok());
        for url in [
            "http://open.feishu.cn/open-apis/bot/v2/hook/id",
            "https://open.feishu.cn.evil/x",
            "https://open.feishu.cn/open-apis/bot/v2/hook/id?x=y",
        ] {
            assert!(validate_url(url).is_err());
        }
    }
    #[test]
    #[cfg(windows)]
    fn dpapi_roundtrip() {
        let encoded = encrypt("test-only-中文").unwrap();
        assert!(!encoded.contains("test-only"));
        assert_eq!(decrypt(&encoded).unwrap(), "test-only-中文");
    }
    #[test]
    fn public_status_never_contains_credentials() {
        let n = Notifier {
            path: PathBuf::new(),
            data: Mutex::new(Stored {
                webhook: "hidden-webhook".into(),
                secret: "hidden-secret".into(),
                ..Stored::default()
            }),
        };
        let text = serde_json::to_string(&n.status()).unwrap();
        assert!(!text.contains("hidden-"));
        assert!(n.status().has_webhook);
    }

    #[test]
    fn retry_queue_survives_restart_and_acknowledges_delivery() {
        let dir = std::env::temp_dir().join(format!(
            "cg-feishu-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let notifier = Notifier {
            path: dir.join("feishu.json"),
            data: Mutex::new(Stored {
                enabled: true,
                ..Stored::default()
            }),
        };
        notifier.observe(false, "代理不可用", None, false, "未确认熔断");
        assert_eq!(notifier.status().queued, 1);
        notifier.deliver_with(|_, _| Err("模拟网络故障".into()));
        let stored: Stored =
            serde_json::from_str(&std::fs::read_to_string(&notifier.path).unwrap()).unwrap();
        assert_eq!(stored.queue[0].attempts, 1);
        assert!(stored.queue[0].next > now());
        let restarted = Notifier {
            path: notifier.path.clone(),
            data: Mutex::new(stored),
        };
        restarted.data.lock().unwrap().queue[0].next = 0;
        restarted.deliver_with(|_, text| {
            assert!(text.contains("未确认熔断"));
            Ok(())
        });
        assert_eq!(restarted.status().queued, 0);
        assert!(restarted.status().last_sent > 0);
        assert!(restarted.status().error.is_empty());
        std::fs::remove_file(&restarted.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn saving_identical_credentials_preserves_pending_and_failed_notifications() {
        let dir = std::env::temp_dir().join(format!(
            "cg-feishu-same-settings-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let url = "https://open.feishu.cn/open-apis/bot/v2/hook/test";
        let webhook = encrypt(url).unwrap();
        let secret = encrypt("test-secret").unwrap();
        let notifier = Notifier {
            path: dir.join("feishu.json"),
            data: Mutex::new(Stored {
                enabled: true,
                webhook: webhook.clone(),
                secret: secret.clone(),
                ..Stored::default()
            }),
        };
        notifier.notify("failed event");
        notifier.deliver_with(|_, _| Err(DeliveryError::permanent("signature rejected")));
        notifier.notify("pending event");
        let before = notifier.data.lock().unwrap().clone();
        let status = notifier
            .configure(Settings {
                enabled: true,
                webhook: Some(format!(" {url} ")),
                secret: Some(" test-secret ".into()),
                clear_secret: false,
            })
            .unwrap();
        assert_eq!(status.queued, 1);
        assert_eq!(status.failed, 1);
        let saved: Stored =
            serde_json::from_str(&std::fs::read_to_string(&notifier.path).unwrap()).unwrap();
        assert_eq!(saved.webhook, webhook);
        assert_eq!(saved.secret, secret);
        assert_eq!(saved.queue[0].id, before.queue[0].id);
        assert_eq!(saved.failed[0].event.id, before.failed[0].event.id);

        // An actual endpoint change must still discard messages for the old group.
        let changed = notifier
            .configure(Settings {
                enabled: true,
                webhook: Some("https://open.feishu.cn/open-apis/bot/v2/hook/other".into()),
                secret: None,
                clear_secret: false,
            })
            .unwrap();
        assert_eq!(changed.queued, 0);
        assert_eq!(changed.failed, 0);
        std::fs::remove_file(&notifier.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn disable_clears_queue_and_empty_inputs_preserve_secrets() {
        let dir = std::env::temp_dir().join(format!(
            "cg-feishu-settings-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let notifier = Notifier {
            path: dir.join("feishu.json"),
            data: Mutex::new(Stored {
                enabled: true,
                webhook: encrypt("https://open.feishu.cn/open-apis/bot/v2/hook/test").unwrap(),
                secret: encrypt("test-secret").unwrap(),
                ..Stored::default()
            }),
        };
        notifier.observe(false, "test", None, false, "test");
        let settings = Settings {
            enabled: false,
            webhook: None,
            secret: None,
            clear_secret: false,
        };
        let status = notifier.configure(settings).unwrap();
        assert!(!status.enabled);
        assert!(status.has_webhook && status.has_secret);
        assert_eq!(status.queued, 0);
        assert_eq!(
            decrypt(&notifier.data.lock().unwrap().secret).unwrap(),
            "test-secret"
        );
        std::fs::remove_file(&notifier.path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
