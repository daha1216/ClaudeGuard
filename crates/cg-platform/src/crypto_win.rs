//! Native Win32 DPAPI secret storage (`CryptProtectData` / `CryptUnprotectData`) and
//! Feishu HMAC-SHA256 webhook signature helpers.

use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::traits::{PlatformError, PlatformResult};

/// Hard cap matching legacy `feishu.rs` credential size limits.
pub const MAX_SECRET_BYTES: usize = 65_536;

/// DPAPI encryption key binding scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpapiScope {
    /// Bound to current Windows user profile (recommended for user-owned config).
    CurrentUser,
    /// Bound to local machine (usable by `LocalSystem` Windows Service across restarts).
    LocalMachine,
}

/// Protect plaintext bytes via Win32 DPAPI (`CryptProtectData`).
#[cfg(windows)]
pub fn protect_bytes(plaintext: &[u8], scope: DpapiScope) -> PlatformResult<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(PlatformError::InvalidInput(format!(
            "secret length {} exceeds {MAX_SECRET_BYTES} bytes",
            plaintext.len()
        )));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | match scope {
            DpapiScope::CurrentUser => 0,
            DpapiScope::LocalMachine => CRYPTPROTECT_LOCAL_MACHINE,
        };

    struct LocalMemGuard(*mut u8);
    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0.cast()));
                }
            }
        }
    }

    unsafe {
        CryptProtectData(&input, None, None, None, None, flags, &mut output)
            .map_err(|e| PlatformError::Io(format!("CryptProtectData failed: {e}")))?;
        let _guard = LocalMemGuard(output.pbData);
        if output.cbData == 0 || output.pbData.is_null() {
            Ok(Vec::new())
        } else {
            Ok(core::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
        }
    }
}

/// Unprotect DPAPI ciphertext via Win32 `CryptUnprotectData`.
#[cfg(windows)]
pub fn unprotect_bytes(ciphertext: &[u8]) -> PlatformResult<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if ciphertext.is_empty() || ciphertext.len() > MAX_SECRET_BYTES * 2 {
        return Err(PlatformError::InvalidInput(
            "DPAPI ciphertext length invalid".to_string(),
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    struct LocalMemGuard(*mut u8);
    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0.cast()));
                }
            }
        }
    }

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| PlatformError::Io(format!("CryptUnprotectData failed: {e}")))?;
        let _guard = LocalMemGuard(output.pbData);
        if output.cbData == 0 || output.pbData.is_null() {
            Ok(Vec::new())
        } else {
            Ok(core::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
        }
    }
}

#[cfg(not(windows))]
pub fn protect_bytes(_plaintext: &[u8], _scope: DpapiScope) -> PlatformResult<Vec<u8>> {
    Err(PlatformError::unsupported(
        "dpapi_secrets",
        "Win32 DPAPI is only supported on Windows",
    ))
}

#[cfg(not(windows))]
pub fn unprotect_bytes(_ciphertext: &[u8]) -> PlatformResult<Vec<u8>> {
    Err(PlatformError::unsupported(
        "dpapi_secrets",
        "Win32 DPAPI is only supported on Windows",
    ))
}

/// Encrypt a UTF-8 secret and encode as Base64.
pub fn protect_str_base64(secret: &str, scope: DpapiScope) -> PlatformResult<String> {
    let cipher = protect_bytes(secret.as_bytes(), scope)?;
    Ok(STANDARD.encode(cipher))
}

/// Decode Base64 and decrypt a UTF-8 secret.
pub fn unprotect_str_base64(encoded: &str) -> PlatformResult<String> {
    let raw = STANDARD
        .decode(encoded.trim())
        .map_err(|_| PlatformError::InvalidInput("invalid base64 DPAPI payload".to_string()))?;
    let plain = unprotect_bytes(&raw)?;
    String::from_utf8(plain)
        .map_err(|_| PlatformError::InvalidInput("decrypted secret is not valid UTF-8".to_string()))
}

/// Compute Feishu custom-bot HMAC-SHA256 signature for `"{timestamp}\n{secret}"`.
pub fn feishu_webhook_sign(secret: &str, timestamp: u64) -> String {
    let key = format!("{timestamp}\n{secret}");
    let mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC-SHA256 accepts arbitrary key length");
    STANDARD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feishu_hmac_signature_is_deterministic_base64() {
        let sig1 = feishu_webhook_sign("my-secret", 1_700_000_000);
        let sig2 = feishu_webhook_sign("my-secret", 1_700_000_000);
        let sig3 = feishu_webhook_sign("my-secret", 1_700_000_001);
        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
        let decoded = STANDARD.decode(&sig1).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn invalid_base64_is_rejected_before_dpapi() {
        assert!(unprotect_str_base64("!!!not-base64!!!").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_roundtrip_and_tamper_rejection() {
        let secret = "https://open.feishu.cn/open-apis/bot/v2/hook/test-token-123";
        let enc = protect_str_base64(secret, DpapiScope::CurrentUser)
            .expect("DPAPI CurrentUser encryption should succeed");
        let dec = unprotect_str_base64(&enc).expect("DPAPI decryption should succeed");
        assert_eq!(dec, secret);

        // Oversized input must fail cleanly.
        let huge = vec![b'a'; MAX_SECRET_BYTES + 1];
        assert!(protect_bytes(&huge, DpapiScope::CurrentUser).is_err());

        // Corrupted ciphertext must fail decryption.
        let mut raw = STANDARD.decode(&enc).unwrap();
        if let Some(last) = raw.last_mut() {
            *last ^= 0xFF;
        }
        assert!(unprotect_bytes(&raw).is_err());
    }
}
