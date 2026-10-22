//! Official macOS client updates, isolated from Windows MSIX deployment.
use crate::{
    config::Config,
    macos::package,
    model::{now, TargetState},
    state::AppState,
};
use package::Identity;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub enum Product {
    Claude,
    Codex,
}
impl Product {
    fn key(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Codex => "Codex / ChatGPT",
        }
    }
    fn identity(self) -> Identity {
        match self {
            Self::Claude => Identity {
                bundle_id: "com.anthropic.claudefordesktop",
                team_id: "Q6L2SF6YDW",
            },
            Self::Codex => Identity {
                bundle_id: "com.openai.codex",
                team_id: "2DC432GLL2",
            },
        }
    }
    fn feed(self) -> &'static str {
        match self {
            Self::Claude => "https://downloads.claude.ai/releases/darwin/universal/RELEASES.json",
            Self::Codex => "https://persistent.oaistatic.com/codex-app-prod/appcast.xml",
        }
    }
    fn updater(self, state: &AppState) -> &Updater {
        match self {
            Self::Claude => &state.claude_update,
            Self::Codex => &state.codex_update,
        }
    }
    fn journal(self) -> PathBuf {
        crate::config::config_dir().join(format!("{}-macos-update-journal.json", self.key()))
    }
    fn installed(self) -> Option<PathBuf> {
        let names: &[&str] = match self {
            Self::Claude => &["Claude.app"],
            Self::Codex => &["ChatGPT.app", "Codex.app"],
        };
        let mut roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(home).join("Applications"));
        }
        roots
            .into_iter()
            .flat_map(|root| names.iter().map(move |n| root.join(n)))
            .find(|p| package::info(p).is_ok_and(|i| i.identifier == self.identity().bundle_id))
    }
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Status {
    pub enabled: bool,
    pub phase: String,
    pub installed_version: String,
    pub latest_version: String,
    // Retain an accepted deployment across restarts. A second submission requires
    // the explicit finish action and consumes its authorization before deployment.
    pub pending_version: String,
    pub pending_since: u64,
    pub resume_pending: bool,
    pub resume_after_boot: String,
    pub pending_attention_sent: bool,
    pub last_check: u64,
    pub last_updated: u64,
    pub downloaded: u64,
    pub total: u64,
    pub error: String,
    pub failure_stage: String,
    pub wait_reason: String,
    pub next_check: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Release {
    version: String,
    url: String,
    size: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    status: Status,
    installed: Option<PathBuf>,
    release: Option<Release>,
}
fn stored_from_bytes(bytes: Option<&[u8]>) -> Stored {
    let mut data: Stored = bytes
        .and_then(|data| serde_json::from_slice(data).ok())
        .unwrap_or_default();
    if data.status.phase.is_empty() || data.status.phase == "unsupported" {
        data.status.phase = "idle".into();
    }
    data
}
pub struct Updater {
    product: Product,
    data: Mutex<Stored>,
    busy: AtomicBool,
    path: PathBuf,
}
const INTERVAL: u64 = 7 * 24 * 3600;
fn healthy(state: &AppState) -> bool {
    let enabled: Vec<_> = state
        .statuses()
        .into_iter()
        .filter(|s| s.state != TargetState::Disabled)
        .collect();
    !state.is_tripped()
        && !state.is_paused()
        && !enabled.is_empty()
        && enabled.iter().all(|s| s.state == TargetState::Pass)
}
fn update_context(cfg: &Config) -> serde_json::Value {
    serde_json::json!({"proxyHost": cfg.proxy_host, "proxyPort": cfg.proxy_port, "targets": cfg.targets})
}
fn allowed_url(product: Product, text: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(text).map_err(|_| "更新 URL 无效")?;
    let host = match product {
        Product::Claude => "downloads.claude.ai",
        Product::Codex => "persistent.oaistatic.com",
    };
    if url.scheme() != "https"
        || url.host_str() != Some(host)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|p| p != 443)
    {
        return Err("更新只允许官方 HTTPS 下载域名，已拒绝其他地址".into());
    }
    Ok(url)
}
fn agent(cfg: &Config, proxy: bool) -> Result<ureq::Agent, String> {
    let builder = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(Duration::from_secs(30 * 60))
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(30));
    let builder = if proxy {
        builder.proxy(ureq::Proxy::new(cfg.proxy_url()).map_err(|_| "代理设置无效")?)
    } else {
        builder
    };
    Ok(builder.build())
}
fn response(product: Product, cfg: &Config, text: &str) -> Result<ureq::Response, String> {
    for proxy in [true, false] {
        let client = agent(cfg, proxy)?;
        let mut current = allowed_url(product, text)?;
        for _ in 0..6 {
            let result = client
                .get(current.as_str())
                .set("User-Agent", "ClaudeGuard-Mac-Updater/3.5")
                .call();
            let reply = match result {
                Ok(r) => r,
                Err(ureq::Error::Status(_, r)) => r,
                Err(_) => break,
            };
            match reply.status() {
                200 => return Ok(reply),
                301 | 302 | 303 | 307 | 308 => {
                    let next = current
                        .join(reply.header("Location").ok_or("官方更新重定向缺少目标")?)
                        .map_err(|_| "更新重定向无效")?;
                    current = allowed_url(product, next.as_str())?;
                }
                _ => break,
            }
        }
    }
    Err("无法读取官方更新源；代理和直连均未成功，未下载或安装更新".into())
}
fn release_from_claude(text: &str) -> Result<Release, String> {
    let data: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "Claude 更新清单不是有效 JSON")?;
    let current = data["currentRelease"]
        .as_str()
        .ok_or("Claude 更新清单缺少版本")?;
    package::numeric_version(current)?;
    let item = data["releases"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["version"] == current))
        .ok_or("Claude 更新清单缺少对应发布项")?;
    let update = &item["updateTo"];
    if update["version"] != current {
        return Err("Claude 更新包版本与清单不一致".into());
    }
    let url = update["url"]
        .as_str()
        .ok_or("Claude 更新清单缺少下载地址")?;
    allowed_url(Product::Claude, url)?;
    if !url::Url::parse(url).unwrap().path().ends_with(".zip") {
        return Err("Claude 更新不是 ZIP 应用包".into());
    }
    Ok(Release {
        version: current.into(),
        url: url.into(),
        size: 0,
    })
}
#[derive(Default)]
struct FeedItem {
    version: String,
    url: String,
    size: u64,
    architecture: String,
    minimum: String,
}
fn release_from_codex(
    text: &str,
    architecture: &str,
    system_version: &str,
) -> Result<Release, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut current: Option<FeedItem> = None;
    let mut items = Vec::new();
    let mut deltas = false;
    loop {
        match reader.read_event().map_err(|_| "Codex 更新清单 XML 无效")? {
            Event::Start(e) if e.local_name().as_ref() == b"item" => {
                current = Some(FeedItem::default())
            }
            Event::Start(e) if e.local_name().as_ref() == b"deltas" => deltas = true,
            Event::End(e) if e.local_name().as_ref() == b"deltas" => deltas = false,
            Event::Start(e) if current.is_some() => {
                let field = e.local_name();
                let name = field.as_ref();
                if [
                    b"shortVersionString".as_slice(),
                    b"hardwareRequirements",
                    b"minimumSystemVersion",
                ]
                .contains(&name)
                {
                    let text = reader
                        .read_text(e.name())
                        .map_err(|_| "Codex 更新字段无效")?
                        .into_owned();
                    let item = current.as_mut().unwrap();
                    match name {
                        b"shortVersionString" => item.version = text,
                        b"hardwareRequirements" => item.architecture = text,
                        b"minimumSystemVersion" => item.minimum = text,
                        _ => {}
                    }
                }
            }
            Event::Empty(e)
                if e.local_name().as_ref() == b"enclosure" && current.is_some() && !deltas =>
            {
                let item = current.as_mut().unwrap();
                for attribute in e.attributes() {
                    let a = attribute.map_err(|_| "Codex 更新属性无效")?;
                    let value = a
                        .decode_and_unescape_value(reader.decoder())
                        .map_err(|_| "Codex 更新属性编码无效")?
                        .into_owned();
                    match a.key.local_name().as_ref() {
                        b"url" => item.url = value,
                        b"length" => item.size = value.parse().map_err(|_| "Codex 包大小无效")?,
                        _ => {}
                    }
                }
            }
            Event::End(e) if e.local_name().as_ref() == b"item" => {
                if let Some(item) = current.take() {
                    items.push(item);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let mut candidates = Vec::new();
    for item in items {
        if item.version.is_empty() || item.url.is_empty() {
            continue;
        }
        if !item.architecture.is_empty()
            && item.architecture != architecture
            && !(architecture == "x86_64" && item.architecture == "x64")
        {
            continue;
        }
        if !item.minimum.is_empty() && package::newer(&item.minimum, system_version)? {
            continue;
        }
        allowed_url(Product::Codex, &item.url)?;
        if !url::Url::parse(&item.url).unwrap().path().ends_with(".zip") {
            continue;
        }
        let version = package::numeric_version(&item.version)?;
        candidates.push((
            version,
            Release {
                version: item.version,
                url: item.url,
                size: item.size,
            },
        ));
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    candidates
        .pop()
        .map(|r| r.1)
        .ok_or_else(|| "官方清单没有适合本机架构和系统版本的 Codex 更新".into())
}
fn check(product: Product, cfg: &Config) -> Result<Release, String> {
    let reply = response(product, cfg, product.feed())?;
    let mut bytes = Vec::new();
    reply
        .into_reader()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "读取更新清单失败")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("更新清单超出大小上限".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "更新清单不是 UTF-8")?;
    match product {
        Product::Claude => release_from_claude(text),
        Product::Codex => {
            let output = std::process::Command::new("/usr/bin/sw_vers")
                .arg("-productVersion")
                .output()
                .map_err(|e| e.to_string())?;
            let system = String::from_utf8_lossy(&output.stdout);
            release_from_codex(
                text,
                if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    "x86_64"
                },
                system.trim(),
            )
        }
    }
}
fn download(
    product: Product,
    cfg: &Config,
    release: &Release,
    destination: &Path,
    mut progress: impl FnMut(u64, u64) -> Result<(), String>,
) -> Result<(), String> {
    const MAX: u64 = 2 * 1024 * 1024 * 1024;
    if release.size > MAX {
        return Err("官方更新包超过 2GB 上限".into());
    }
    let reply = response(product, cfg, &release.url)?;
    let total = reply
        .header("Content-Length")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(release.size);
    if total > MAX {
        return Err("更新响应大小超限".into());
    }
    let mut file = std::fs::File::create(destination).map_err(|e| e.to_string())?;
    let mut input = reply.into_reader();
    stream_download(&mut input, &mut file, release.size, total, &mut progress)?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}
fn stream_download(
    input: &mut impl Read,
    output: &mut impl Write,
    expected: u64,
    total: u64,
    mut progress: impl FnMut(u64, u64) -> Result<(), String>,
) -> Result<(), String> {
    const MAX: u64 = 2 * 1024 * 1024 * 1024;
    let mut buffer = [0u8; 65536];
    let mut downloaded = 0u64;
    progress(0, total)?;
    loop {
        let size = input
            .read(&mut buffer)
            .map_err(|_| "更新下载中断，未替换应用")?;
        if size == 0 {
            break;
        }
        downloaded += size as u64;
        if downloaded > MAX {
            return Err("更新下载超出大小上限".into());
        }
        output
            .write_all(&buffer[..size])
            .map_err(|e| e.to_string())?;
        progress(downloaded, total)?;
    }
    if downloaded == 0
        || (expected > 0 && downloaded != expected)
        || (total > 0 && downloaded != total)
    {
        return Err("更新下载不完整，未安装".into());
    }
    Ok(())
}

impl Updater {
    pub fn load(product: Product) -> Self {
        let path = crate::config::config_dir().join(format!("{}-update.json", product.key()));
        let bytes = std::fs::read(&path).ok();
        let data = stored_from_bytes(bytes.as_deref());
        Self {
            product,
            data: Mutex::new(data),
            busy: AtomicBool::new(false),
            path,
        }
    }
    fn normalize_interrupted(&self) -> Result<(), String> {
        if ["checking", "downloading", "verifying", "installing"]
            .contains(&self.status().phase.as_str())
        {
            self.change(|d| {
                d.status.phase = "idle".into();
                d.status.error =
                    "上次更新被中断；下次检查先核对并恢复应用，不会盲目重复安装".into();
                d.status.last_check = 0;
            })?;
        }
        Ok(())
    }
    fn save(&self, data: &Stored) -> Result<(), String> {
        let parent = self.path.parent().ok_or("更新状态路径无效")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let temp = self.path.with_extension("json.tmp");
        std::fs::write(
            &temp,
            serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(temp, &self.path).map_err(|e| e.to_string())
    }
    fn change(&self, update: impl FnOnce(&mut Stored)) -> Result<(), String> {
        let mut data = self.data.lock().map_err(|_| "更新状态锁不可用")?;
        let mut next = data.clone();
        update(&mut next);
        self.save(&next)?;
        *data = next;
        Ok(())
    }
    pub fn status(&self) -> Status {
        let mut status = self.data.lock().unwrap().status.clone();
        if let Some(path) = self.product.installed() {
            if let Ok(info) = package::info(&path) {
                status.installed_version = info.version;
            }
        }
        status
    }
    pub fn configure(&self, enabled: bool) -> Result<Status, String> {
        self.change(|d| {
            d.status.enabled = enabled;
            d.status.error.clear();
            d.status.next_check = 0;
        })?;
        Ok(self.status())
    }
    pub fn start(state: &Arc<AppState>, product: Product) {
        let state = Arc::clone(state);
        std::thread::spawn(move || {
            let updater = product.updater(&state);
            if let Err(error) = updater.normalize_interrupted() {
                let _ = updater.change(|d| {
                    d.status.phase = "failed".into();
                    d.status.error = error;
                });
            }
            let saved = updater.data.lock().unwrap().installed.clone();
            if let Some(path) = saved {
                if let Err(error) = package::recover(&product.journal(), &path, |p| {
                    package::verify_vendor(p, &product.identity()).map(|_| ())
                }) {
                    let _ = updater.change(|d| {
                        d.status.phase = "failed".into();
                        d.status.error = error;
                    });
                }
            }
            while !state.stop.load(Ordering::SeqCst) {
                let status = updater.status();
                let due = now() >= status.next_check
                    && (status.last_check == 0
                        || now().saturating_sub(status.last_check) >= INTERVAL
                        || status.phase == "waiting");
                if status.enabled && due && healthy(&state) {
                    let _ = Self::request(&state, product, false);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }
    pub fn request(state: &Arc<AppState>, product: Product, finish: bool) -> Result<(), String> {
        let updater = product.updater(state);
        if updater.busy.swap(true, Ordering::SeqCst) {
            return Err("此客户端的更新任务正在运行".into());
        }
        let state = Arc::clone(state);
        std::thread::spawn(move || {
            let updater = product.updater(&state);
            let result = updater.perform(&state, finish);
            if let Err(error) = result {
                let _ = updater.change(|d| {
                    d.status.phase = "failed".into();
                    d.status.error = error;
                    d.status.next_check = now() + 300;
                });
            }
            updater.busy.store(false, Ordering::SeqCst);
            state.emit_state();
        });
        Ok(())
    }
    fn perform(&self, state: &Arc<AppState>, finish: bool) -> Result<(), String> {
        self.change(|d| {
            d.status.phase = "checking".into();
            d.status.error.clear();
        })?;
        state.emit_state();
        let destination = self
            .product
            .installed()
            .ok_or("没有找到受支持的官方客户端；更新器不执行首次安装")?;
        package::recover(&self.product.journal(), &destination, |p| {
            package::verify_vendor(p, &self.product.identity()).map(|_| ())
        })?;
        let installed = package::info(&destination)?;
        let cfg = state.config();
        let release = check(self.product, &cfg)?;
        self.change(|d| {
            d.installed = Some(destination.clone());
            d.release = Some(release.clone());
            d.status.installed_version = installed.version.clone();
            d.status.latest_version = release.version.clone();
            d.status.last_check = now();
            d.status.next_check = now() + INTERVAL;
        })?;
        if !package::newer(&release.version, &installed.version)? {
            self.change(|d| {
                d.status.phase = "current".into();
                d.status.pending_version.clear();
                d.status.wait_reason.clear();
            })?;
            return Ok(());
        }
        if !self.status().enabled && !finish {
            self.change(|d| {
                d.status.phase = "available".into();
            })?;
            return Ok(());
        }
        if !healthy(state) || package::running(&destination) {
            self.change(|d| {
                d.status.phase = "waiting".into();
                d.status.wait_reason =
                    "等待全部出口检查通过并且客户端自行退出；不会强制结束应用".into();
                d.status.pending_version = release.version.clone();
                d.status.next_check = now() + 30;
            })?;
            return Ok(());
        }
        package::verify_vendor(&destination, &self.product.identity())?;
        let temp = tempfile::Builder::new()
            .prefix("claudeguard-client-")
            .tempdir()
            .map_err(|e| e.to_string())?;
        let archive = temp.path().join("update.zip");
        self.change(|d| {
            d.status.phase = "downloading".into();
            d.status.wait_reason.clear();
            d.status.downloaded = 0;
            d.status.total = release.size;
        })?;
        state.emit_state();
        let context = update_context(&cfg);
        let permitted = || {
            update_context(&state.config()) == context
                && !state.stop.load(Ordering::SeqCst)
                && healthy(state)
                && (finish || self.status().enabled)
        };
        let mut last = 0u64;
        download(self.product, &cfg, &release, &archive, |done, total| {
            if !permitted() {
                return Err("更新已取消：守护条件、设置或退出状态改变，未替换客户端".into());
            }
            if done.saturating_sub(last) > 1024 * 1024 || done == total {
                last = done;
                let _ = self.change(|d| {
                    d.status.downloaded = done;
                    d.status.total = total;
                });
                state.emit_state();
            }
            Ok(())
        })?;
        self.change(|d| d.status.phase = "verifying".into())?;
        state.emit_state();
        let candidate = package::extract(&archive, &temp.path().join("expanded"))?;
        let verified = package::verify_vendor(&candidate, &self.product.identity())?;
        if verified.version != release.version {
            return Err("签名应用版本与官方更新清单不一致，未安装".into());
        }
        if !permitted() {
            return Err("更新准备期间守护条件或自动更新设置改变，未替换客户端".into());
        }
        self.change(|d| d.status.phase = "installing".into())?;
        state.emit_state();
        let _backup = package::replace(
            &candidate,
            &destination,
            &self.product.journal(),
            |p| package::verify_vendor(p, &self.product.identity()).map(|_| ()),
            |path| !permitted() || package::running(path),
        )?;
        self.change(|d| {
            d.status.phase = "updated".into();
            d.status.last_updated = now();
            d.status.installed_version = release.version.clone();
            d.status.pending_version.clear();
            d.status.wait_reason.clear();
        })?;
        state.notify(
            "client_update",
            &format!("{} 更新完成", self.product.name()),
            &format!("已安装官方版本 {}；旧版本备份已保留。", release.version),
        );
        Ok(())
    }
}
/// Read-only online check used for live verification. Does not save, enable or install.
pub fn check_only(product: Product, cfg: &Config) -> Result<serde_json::Value, String> {
    let release = check(product, cfg)?;
    let installed = product.installed().and_then(|p| package::info(&p).ok());
    Ok(
        serde_json::json!({"product":product.key(),"latestVersion":release.version,"installedVersion":installed.as_ref().map(|i|&i.version),"updateAvailable":installed.as_ref().map(|i|package::newer(&release.version,&i.version)).transpose()?,"source":"official","installed":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn claude_manifest_binds_version_and_official_domain() {
        let good = r#"{"currentRelease":"3.1.0","releases":[{"version":"3.1.0","updateTo":{"version":"3.1.0","url":"https://downloads.claude.ai/releases/darwin/universal/3.1.0/Claude.zip"}}]}"#;
        assert_eq!(release_from_claude(good).unwrap().version, "3.1.0");
        assert!(release_from_claude(&good.replace("downloads.claude.ai", "evil.example")).is_err());
        assert!(release_from_claude(&good.replace(
            "\"version\":\"3.1.0\",\"url\"",
            "\"version\":\"3.2.0\",\"url\""
        ))
        .is_err());
        assert!(allowed_url(Product::Codex, "http://persistent.oaistatic.com/u.zip").is_err());
        assert!(allowed_url(
            Product::Codex,
            "https://persistent.oaistatic.com.evil/u.zip"
        )
        .is_err());
    }
    #[test]
    fn sparkle_selects_architecture_system_and_full_zip_ignoring_deltas() {
        let feed = r#"<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item><sparkle:shortVersionString>26.10.1</sparkle:shortVersionString><sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion><sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements><enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT.zip" length="42"/><sparkle:deltas><enclosure url="https://evil.example/payload.delta" length="2"/></sparkle:deltas></item></channel></rss>"#;
        let release = release_from_codex(feed, "arm64", "26.0").unwrap();
        assert!(release.url.ends_with("ChatGPT.zip"));
        assert_eq!(release.size, 42);
        assert!(release_from_codex(feed, "x86_64", "26.0").is_err());
        assert!(release_from_codex(feed, "arm64", "12.0").is_err());
    }
    #[test]
    #[ignore = "read-only verification of the installed official apps' signature, publisher, trust and architecture"]
    fn real_installed_vendor_identity_and_trust() {
        for product in [Product::Claude, Product::Codex] {
            let path = product
                .installed()
                .expect("official app must be installed for this test");
            let info = package::verify_vendor(&path, &product.identity()).unwrap();
            assert_eq!(info.identifier, product.identity().bundle_id);
        }
    }
    #[test]
    #[ignore = "downloads official signed client archives into a temporary directory; never installs or launches"]
    fn official_download_extract_and_verify() {
        let selected =
            std::env::var("CG_CLIENT_VERIFY_PRODUCT").unwrap_or_else(|_| "claude".into());
        let product = match selected.as_str() {
            "claude" => Product::Claude,
            "codex" => Product::Codex,
            _ => panic!("CG_CLIENT_VERIFY_PRODUCT must be claude or codex"),
        };
        let cfg = Config::default(); // Deliberately never read the user's configuration.
        let release = check(product, &cfg).expect("official feed");
        let temp = tempfile::Builder::new()
            .prefix("claudeguard-official-test-")
            .tempdir()
            .unwrap();
        let archive = temp.path().join("official.zip");
        download(product, &cfg, &release, &archive, |_, _| Ok(()))
            .expect("complete official download");
        let candidate = package::extract(&archive, &temp.path().join("expanded"))
            .expect("safe archive extraction");
        let verified = package::verify_vendor(&candidate, &product.identity())
            .expect("official signature, publisher, Gatekeeper and architecture");
        assert_eq!(verified.version, release.version);
        println!(
            "verified official {} {} archive; no installation or launch performed",
            product.key(),
            verified.version
        );
    }
    #[test]
    fn download_stream_rejects_truncation_and_honors_cancellation() {
        let mut bytes = Vec::new();
        assert!(stream_download(&mut &b"short"[..], &mut bytes, 6, 6, |_, _| Ok(())).is_err());
        assert!(stream_download(&mut &b""[..], &mut bytes, 0, 0, |_, _| Ok(())).is_err());
        bytes.clear();
        assert!(
            stream_download(&mut &b"valid"[..], &mut bytes, 5, 5, |done, _| {
                if done == 0 {
                    Err("cancelled".into())
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert!(bytes.is_empty());
        stream_download(&mut &b"valid"[..], &mut bytes, 5, 5, |_, _| Ok(())).unwrap();
        assert_eq!(bytes, b"valid");
        bytes.clear();
        let large = vec![0u8; 128 * 1024];
        assert!(stream_download(
            &mut large.as_slice(),
            &mut bytes,
            large.len() as u64,
            large.len() as u64,
            |done, _| {
                if done > 0 {
                    Err("settings changed during transfer".into())
                } else {
                    Ok(())
                }
            }
        )
        .is_err());
        assert_eq!(bytes.len(), 65536);
    }
    #[test]
    fn status_load_preserves_active_phase_for_read_only_cli() {
        let stored = Stored {
            status: Status {
                phase: "downloading".into(),
                downloaded: 42,
                total: 100,
                ..Status::default()
            },
            ..Stored::default()
        };
        let decoded = stored_from_bytes(Some(&serde_json::to_vec(&stored).unwrap()));
        assert_eq!(decoded.status.phase, "downloading");
        assert_eq!(decoded.status.downloaded, 42);

        let empty = stored_from_bytes(Some(b"{}"));
        assert_eq!(empty.status.phase, "idle");
    }
}
