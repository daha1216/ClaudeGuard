//! Shared Windows COM / WinRT apartment helper (MTA with safe STA coexistence).

use crate::traits::{PlatformError, PlatformResult};

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;
const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;

/// RAII guard ensuring COM is initialized on the calling thread (`COINIT_MULTITHREADED`)
/// and balanced with `CoUninitialize` only when this guard initialized it.
pub(crate) struct ComGuard {
    should_uninit: bool,
}

impl ComGuard {
    pub(crate) fn init_mta() -> PlatformResult<Self> {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        match hr.0 {
            S_OK | S_FALSE => Ok(Self {
                should_uninit: true,
            }),
            // Thread already initialized as STA (e.g. UI/test runner); safe to proceed without uninit.
            RPC_E_CHANGED_MODE => Ok(Self {
                should_uninit: false,
            }),
            code => Err(PlatformError::Com {
                code,
                context: "CoInitializeEx(COINIT_MULTITHREADED)".to_string(),
            }),
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe {
                windows::Win32::System::Com::CoUninitialize();
            }
        }
    }
}

pub(crate) fn map_win_err(err: windows::core::Error, context: &str) -> PlatformError {
    let code = err.code().0;
    if code == E_ACCESSDENIED {
        PlatformError::AccessDenied(format!("{context}: {err}"))
    } else {
        PlatformError::Com {
            code,
            context: format!("{context}: {err}"),
        }
    }
}
