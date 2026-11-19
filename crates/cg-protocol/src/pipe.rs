//! Named Pipe wire protocol (`PipeRequest` / `PipeResponse`) and 4-byte LE framing.

use crate::config::Config;
use crate::model::{LogEntry, OnboardingProbeResult, PolicyPreset};
use crate::snapshot::GuardSnapshot;
use crate::state::OperationReceipt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};

/// Default Windows Named Pipe path for daemon <-> GUI/CLI IPC.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\ClaudeGuardV4";

/// Maximum frame payload size (4 MiB).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Structured IPC error category returned inside [`PipeResponse::Error`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    ValidationFailed,
    IllegalState,
    IoFailed,
    Unsupported,
    NotFound,
    Busy,
    #[default]
    Internal,
}

/// Requests sent from GUI/CLI clients to the daemon over the Named Pipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PipeRequest {
    GetSnapshot,
    RecheckNow {
        #[serde(default)]
        target_id: Option<String>,
    },
    SetPolicyPreset {
        preset: PolicyPreset,
    },
    SaveConfig {
        config: Config,
    },
    Pause {
        /// Pause duration in seconds (`None` or `Some(0)` clears an active pause).
        #[serde(default)]
        duration_secs: Option<u64>,
    },
    SetManualLockdown {
        on: bool,
    },
    RecoverSafeFlowA,
    DisarmAndRestoreFlowB {
        #[serde(default)]
        reason: Option<String>,
    },
    Rearm,
    CheckLaunchGate {
        #[serde(default)]
        agent_id: Option<String>,
    },
    SweepOrphans,
    ProbeOnboarding,
    CompleteOnboarding {
        config: Config,
    },
    QueryLogs {
        #[serde(default)]
        since_ts: Option<u64>,
        #[serde(default)]
        until_ts: Option<u64>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        query: Option<String>,
    },
    CheckUpdates {
        #[serde(default)]
        component: Option<String>,
    },
    ForceKillAgent {
        #[serde(default)]
        agent_id: Option<String>,
        #[serde(default = "crate::model::default_true")]
        include_cli: bool,
    },
    SaveFeishuConfig {
        enabled: bool,
        #[serde(default)]
        webhook: Option<String>,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        clear_secret: bool,
    },
    TestFeishu {
        #[serde(default)]
        webhook: Option<String>,
        #[serde(default)]
        secret: Option<String>,
    },
    SyncLeakShield,
    SwitchProxyNode {
        group: String,
        node: String,
        #[serde(default = "crate::model::default_true")]
        close_connections: bool,
    },
    RepairAntigravityProxy,
    ApplyEnvAlignment {
        #[serde(default = "crate::model::default_true")]
        align_tz: bool,
        #[serde(default)]
        align_location: bool,
    },
    RollbackEnvAlignment,
    ExportDiagnostics,
}

/// Responses sent from the daemon back to GUI/CLI clients over the Named Pipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum PipeResponse {
    Snapshot {
        snapshot: Box<GuardSnapshot>,
    },
    Ack {
        #[serde(default)]
        receipt: Option<OperationReceipt>,
        #[serde(default)]
        snapshot: Option<Box<GuardSnapshot>>,
    },
    LaunchGate {
        allowed: bool,
        reason: String,
        #[serde(default)]
        snapshot: Option<Box<GuardSnapshot>>,
    },
    OnboardingProbe {
        probe: OnboardingProbeResult,
    },
    Logs {
        entries: Vec<LogEntry>,
        total: usize,
    },
    Error {
        code: ErrorCode,
        message: String,
        #[serde(default)]
        receipt: Option<OperationReceipt>,
    },
}

/// Wire framing error for 4-byte LE length-prefixed JSON messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    ZeroLength,
    TooLarge { len: usize, max: usize },
    TruncatedHeader { available: usize },
    IncompletePayload { expected: usize, available: usize },
    TrailingBytes { expected: usize, actual: usize },
    EncodeFailed(String),
    DecodeFailed(String),
    Io(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLength => f.write_str("frame length cannot be zero"),
            Self::TooLarge { len, max } => {
                write!(f, "frame length {len} exceeds maximum {max} bytes")
            }
            Self::TruncatedHeader { available } => {
                write!(f, "truncated 4-byte frame header (got {available} bytes)")
            }
            Self::IncompletePayload {
                expected,
                available,
            } => write!(
                f,
                "incomplete frame payload: expected {expected} bytes, got {available}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                f,
                "frame buffer has trailing bytes: expected {expected} total bytes, got {actual}"
            ),
            Self::EncodeFailed(err) => write!(f, "frame JSON encode failed: {err}"),
            Self::DecodeFailed(err) => write!(f, "frame JSON decode failed: {err}"),
            Self::Io(err) => write!(f, "frame I/O error: {err}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for String {
    fn from(err: FrameError) -> Self {
        err.to_string()
    }
}

/// Encodes `msg` as `[u32 LE length][UTF-8 JSON payload]`, enforcing [`MAX_FRAME_BYTES`].
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(msg).map_err(|e| FrameError::EncodeFailed(e.to_string()))?;
    let len = payload.len();
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decodes a single complete length-prefixed JSON frame from `buf`.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<T, FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::TruncatedHeader {
            available: buf.len(),
        });
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let total = 4 + len;
    if buf.len() < total {
        return Err(FrameError::IncompletePayload {
            expected: len,
            available: buf.len() - 4,
        });
    }
    if buf.len() > total {
        return Err(FrameError::TrailingBytes {
            expected: total,
            actual: buf.len(),
        });
    }
    serde_json::from_slice(&buf[4..total]).map_err(|e| FrameError::DecodeFailed(e.to_string()))
}

/// Streaming frame decoder returning `Ok(None)` when more bytes are needed, or `Ok(Some((msg, consumed)))`.
pub fn try_decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let total = 4 + len;
    if buf.len() < total {
        return Ok(None);
    }
    let value = serde_json::from_slice(&buf[4..total])
        .map_err(|e| FrameError::DecodeFailed(e.to_string()))?;
    Ok(Some((value, total)))
}

/// Writes a framed message to a synchronous stream.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), FrameError> {
    let bytes = encode_frame(msg)?;
    writer
        .write_all(&bytes)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    writer.flush().map_err(|e| FrameError::Io(e.to_string()))
}

/// Reads a single framed message from a synchronous stream.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_BYTES,
        });
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| FrameError::Io(e.to_string()))?;
    serde_json::from_slice(&payload).map_err(|e| FrameError::DecodeFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessEvidence, AccessLevel, PolicyPreset};

    #[test]
    fn pipe_request_and_response_tags_use_expected_wire_format() {
        let req = PipeRequest::SetPolicyPreset {
            preset: PolicyPreset::StrictStaticIp,
        };
        let json = serde_json::to_string(&req).expect("serialize req");
        assert!(json.contains(r#""op":"set_policy_preset""#));
        assert!(json.contains(r#""preset":"strict_static_ip""#));
        let parsed: PipeRequest = serde_json::from_str(&json).expect("deserialize req");
        assert_eq!(parsed, req);

        // Optional fields omitted should deserialize with defaults.
        let bare_recheck: PipeRequest =
            serde_json::from_str(r#"{"op":"recheck_now"}"#).expect("bare recheck_now");
        assert_eq!(bare_recheck, PipeRequest::RecheckNow { target_id: None });

        let bare_kill: PipeRequest =
            serde_json::from_str(r#"{"op":"force_kill_agent"}"#).expect("bare force_kill_agent");
        assert_eq!(
            bare_kill,
            PipeRequest::ForceKillAgent {
                agent_id: None,
                include_cli: true
            }
        );

        let resp = PipeResponse::LaunchGate {
            allowed: false,
            reason: "出口未验证".into(),
            snapshot: None,
        };
        let rjson = serde_json::to_string(&resp).expect("serialize resp");
        assert!(rjson.contains(r#""status":"launch_gate""#));
        assert_eq!(
            serde_json::from_str::<PipeResponse>(&rjson).expect("deserialize resp"),
            resp
        );
    }

    #[test]
    fn roundtrips_all_sixteen_pipe_request_variants() {
        let all = vec![
            PipeRequest::GetSnapshot,
            PipeRequest::RecheckNow {
                target_id: Some("claude".into()),
            },
            PipeRequest::SetPolicyPreset {
                preset: PolicyPreset::LooseAntiDirect,
            },
            PipeRequest::SaveConfig {
                config: Config::default(),
            },
            PipeRequest::Pause {
                duration_secs: Some(1800),
            },
            PipeRequest::SetManualLockdown { on: true },
            PipeRequest::RecoverSafeFlowA,
            PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("user requested".into()),
            },
            PipeRequest::Rearm,
            PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            },
            PipeRequest::SweepOrphans,
            PipeRequest::ProbeOnboarding,
            PipeRequest::CompleteOnboarding {
                config: Config::default(),
            },
            PipeRequest::QueryLogs {
                since_ts: Some(100),
                until_ts: Some(200),
                limit: Some(50),
                query: Some("trip".into()),
            },
            PipeRequest::CheckUpdates {
                component: Some("antigravity_proxy".into()),
            },
            PipeRequest::ForceKillAgent {
                agent_id: Some("claude".into()),
                include_cli: false,
            },
            PipeRequest::SaveFeishuConfig {
                enabled: true,
                webhook: Some("https://open.feishu.cn/open-apis/bot/v2/hook/demo-token".into()),
                secret: Some("demo-secret".into()),
                clear_secret: false,
            },
            PipeRequest::TestFeishu {
                webhook: None,
                secret: None,
            },
            PipeRequest::SyncLeakShield,
            PipeRequest::SwitchProxyNode {
                group: "Proxy".into(),
                node: "US-LAX-01".into(),
                close_connections: true,
            },
            PipeRequest::RepairAntigravityProxy,
            PipeRequest::ApplyEnvAlignment {
                align_tz: true,
                align_location: false,
            },
            PipeRequest::RollbackEnvAlignment,
            PipeRequest::ExportDiagnostics,
        ];
        assert_eq!(all.len(), 24);
        for req in all {
            let frame = encode_frame(&req).expect("encode");
            let decoded: PipeRequest = decode_frame(&frame).expect("decode");
            assert_eq!(decoded, req);
        }
    }

    #[test]
    fn frame_codec_enforces_le_length_and_4mib_cap() {
        let resp = PipeResponse::OnboardingProbe {
            probe: OnboardingProbeResult {
                access: AccessEvidence {
                    level: AccessLevel::SystemProxy,
                    proxy_addr: Some("127.0.0.1:7890".into()),
                    observed_at: 1_700_000_000,
                    revision: 1,
                    ..AccessEvidence::default()
                },
                detected_proxy_port: Some(7890),
                ..OnboardingProbeResult::default()
            },
        };
        let mut buf = encode_frame(&resp).expect("encode");
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(len + 4, buf.len());

        // Stream roundtrip
        let mut cursor = std::io::Cursor::new(Vec::new());
        write_frame(&mut cursor, &resp).expect("write_frame");
        cursor.set_position(0);
        let read_back: PipeResponse = read_frame(&mut cursor).expect("read_frame");
        assert_eq!(read_back, resp);

        // Partial frame in try_decode_frame
        assert!(
            try_decode_frame::<PipeResponse>(&buf[..3])
                .expect("short header")
                .is_none()
        );
        assert!(
            try_decode_frame::<PipeResponse>(&buf[..buf.len() - 1])
                .expect("short body")
                .is_none()
        );

        // Exact frame rejects trailing bytes
        buf.push(b' ');
        assert!(matches!(
            decode_frame::<PipeResponse>(&buf),
            Err(FrameError::TrailingBytes { .. })
        ));

        // Zero length and > 4 MiB rejected
        assert_eq!(
            decode_frame::<PipeRequest>(&0u32.to_le_bytes()),
            Err(FrameError::ZeroLength)
        );
        let too_big = ((MAX_FRAME_BYTES as u32) + 1).to_le_bytes();
        assert!(matches!(
            decode_frame::<PipeRequest>(&too_big),
            Err(FrameError::TooLarge { .. })
        ));

        let huge = "x".repeat(MAX_FRAME_BYTES + 16);
        assert!(matches!(
            encode_frame(&huge),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn roundtrips_all_pipe_response_variants_and_concatenated_stream() {
        let responses = vec![
            PipeResponse::Snapshot {
                snapshot: Box::default(),
            },
            PipeResponse::Ack {
                receipt: Some(OperationReceipt::default()),
                snapshot: Some(Box::default()),
            },
            PipeResponse::LaunchGate {
                allowed: true,
                reason: String::new(),
                snapshot: None,
            },
            PipeResponse::OnboardingProbe {
                probe: OnboardingProbeResult::default(),
            },
            PipeResponse::Logs {
                entries: vec![LogEntry::default()],
                total: 1,
            },
            PipeResponse::Error {
                code: ErrorCode::ValidationFailed,
                message: "invalid url".into(),
                receipt: None,
            },
        ];

        let mut stream = Vec::new();
        for resp in &responses {
            stream.extend_from_slice(&encode_frame(resp).expect("encode"));
        }

        let mut offset = 0usize;
        let mut decoded = Vec::new();
        while let Some((msg, used)) =
            try_decode_frame::<PipeResponse>(&stream[offset..]).expect("stream")
        {
            decoded.push(msg);
            offset += used;
        }
        assert_eq!(offset, stream.len());
        assert_eq!(decoded, responses);
    }
}
