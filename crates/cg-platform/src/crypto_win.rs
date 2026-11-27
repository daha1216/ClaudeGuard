//! Native Win32 DPAPI secret storage (`CryptProtectData` / `CryptUnprotectData`),
//! Feishu HMAC-SHA256 webhook signature helpers, and Windows CNG AES-256-GCM + DPAPI
//! `CGBAK005` envelope encryption for Clean-Room backups.

use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::traits::{PlatformError, PlatformResult};

/// Hard cap matching legacy `feishu.rs` credential size limits.
pub const MAX_SECRET_BYTES: usize = 65_536;

/// Magic header for ClaudeGuard v5 Clean-Room encrypted backup envelopes.
pub const CGBAK_MAGIC: &[u8; 8] = b"CGBAK005";

/// AES-256 key size in bytes.
pub const AES256_KEY_LEN: usize = 32;

/// AES-GCM 96-bit nonce size in bytes.
pub const AES_GCM_NONCE_LEN: usize = 12;

/// AES-GCM 128-bit authentication tag size in bytes.
pub const AES_GCM_TAG_LEN: usize = 16;

/// Maximum plaintext payload allowed inside a single `.cgbak` envelope (64 MiB).
pub const MAX_CGBAK_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum serialized `.cgbak` envelope size accepted for decryption.
pub const MAX_CGBAK_ENVELOPE_BYTES: usize = MAX_CGBAK_PLAINTEXT_BYTES + 256 * 1024;

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

/// Compute lowercase hexadecimal SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for b in digest {
        use core::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Fill `out` with cryptographically secure random bytes via Windows CNG `BCryptGenRandom`.
#[cfg(windows)]
pub fn random_bytes(out: &mut [u8]) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };

    if out.is_empty() {
        return Ok(());
    }
    let status = unsafe { BCryptGenRandom(None, out, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_ok() {
        Ok(())
    } else {
        Err(format!(
            "BCryptGenRandom failed with NTSTATUS 0x{:08X}",
            status.0 as u32
        ))
    }
}

#[cfg(not(windows))]
pub fn random_bytes(out: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    if out.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
    f.read_exact(out)
        .map_err(|e| format!("failed to read /dev/urandom: {e}"))
}

/// Generate `byte_len` cryptographically secure random bytes encoded as lowercase hex (`2 * byte_len` chars).
pub fn random_hex(byte_len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; byte_len];
    random_bytes(&mut buf)?;
    let mut hex = String::with_capacity(byte_len * 2);
    for b in buf {
        use core::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Generate a cryptographically random RFC 4122 UUIDv4 string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`).
pub fn random_uuid_v4() -> Result<String, String> {
    let mut b = [0u8; 16];
    random_bytes(&mut b)?;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    ))
}

#[cfg(windows)]
mod cng_gcm {
    use core::ffi::c_void;

    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt,
        BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider, BCryptSetProperty,
        BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_CHAINING_MODE, BCRYPT_FLAGS,
        BCRYPT_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    };

    struct AlgGuard(BCRYPT_ALG_HANDLE);
    impl Drop for AlgGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = BCryptCloseAlgorithmProvider(self.0, 0);
                }
            }
        }
    }

    struct KeyGuard(BCRYPT_KEY_HANDLE);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = BCryptDestroyKey(self.0);
                }
            }
        }
    }

    /// UTF-16LE bytes of `"ChainingModeGCM\0"` (`BCRYPT_CHAIN_MODE_GCM`).
    fn gcm_mode_utf16_bytes() -> [u8; 32] {
        let wide: [u16; 16] = [
            b'C' as u16,
            b'h' as u16,
            b'a' as u16,
            b'i' as u16,
            b'n' as u16,
            b'i' as u16,
            b'n' as u16,
            b'g' as u16,
            b'M' as u16,
            b'o' as u16,
            b'd' as u16,
            b'e' as u16,
            b'G' as u16,
            b'C' as u16,
            b'M' as u16,
            0,
        ];
        let mut out = [0u8; 32];
        for (idx, unit) in wide.iter().enumerate() {
            let le = unit.to_le_bytes();
            out[idx * 2] = le[0];
            out[idx * 2 + 1] = le[1];
        }
        out
    }

    fn open_aes_gcm_key(key_32: &[u8; 32]) -> Result<(AlgGuard, KeyGuard), String> {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg,
                BCRYPT_AES_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        };
        if !status.is_ok() {
            return Err(format!(
                "BCryptOpenAlgorithmProvider(AES) failed: 0x{:08X}",
                status.0 as u32
            ));
        }
        let alg_guard = AlgGuard(alg);

        let gcm_bytes = gcm_mode_utf16_bytes();
        let status = unsafe {
            BCryptSetProperty(
                BCRYPT_HANDLE(alg_guard.0 .0),
                BCRYPT_CHAINING_MODE,
                &gcm_bytes,
                0,
            )
        };
        if !status.is_ok() {
            return Err(format!(
                "BCryptSetProperty(ChainingModeGCM) failed: 0x{:08X}",
                status.0 as u32
            ));
        }

        let mut key = BCRYPT_KEY_HANDLE::default();
        let status = unsafe { BCryptGenerateSymmetricKey(alg_guard.0, &mut key, None, key_32, 0) };
        if !status.is_ok() {
            return Err(format!(
                "BCryptGenerateSymmetricKey failed: 0x{:08X}",
                status.0 as u32
            ));
        }
        Ok((alg_guard, KeyGuard(key)))
    }

    pub fn encrypt(
        key_32: &[u8; 32],
        nonce_12: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), String> {
        if plaintext.len() > u32::MAX as usize || aad.len() > u32::MAX as usize {
            return Err("AES-256-GCM input exceeds CNG 32-bit length bound".into());
        }
        let (_alg, key) = open_aes_gcm_key(key_32)?;

        let mut nonce = *nonce_12;
        let mut tag = [0u8; 16];
        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_mut_ptr(),
            cbNonce: nonce.len() as u32,
            pbAuthData: if aad.is_empty() {
                core::ptr::null_mut()
            } else {
                aad.as_ptr().cast_mut()
            },
            cbAuthData: aad.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: tag.len() as u32,
            ..Default::default()
        };

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut written: u32 = 0;
        let status = unsafe {
            BCryptEncrypt(
                key.0,
                if plaintext.is_empty() {
                    None
                } else {
                    Some(plaintext)
                },
                Some(
                    (&mut auth_info as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO).cast::<c_void>(),
                ),
                None,
                if ciphertext.is_empty() {
                    None
                } else {
                    Some(ciphertext.as_mut_slice())
                },
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };
        if !status.is_ok() {
            return Err(format!(
                "BCryptEncrypt(AES-256-GCM) failed: 0x{:08X}",
                status.0 as u32
            ));
        }
        ciphertext.truncate(written as usize);
        Ok((ciphertext, tag))
    }

    pub fn decrypt(
        key_32: &[u8; 32],
        nonce_12: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag_16: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        if ciphertext.len() > u32::MAX as usize || aad.len() > u32::MAX as usize {
            return Err("AES-256-GCM input exceeds CNG 32-bit length bound".into());
        }
        let (_alg, key) = open_aes_gcm_key(key_32)?;

        let mut nonce = *nonce_12;
        let mut tag = *tag_16;
        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            cbSize: core::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_mut_ptr(),
            cbNonce: nonce.len() as u32,
            pbAuthData: if aad.is_empty() {
                core::ptr::null_mut()
            } else {
                aad.as_ptr().cast_mut()
            },
            cbAuthData: aad.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: tag.len() as u32,
            ..Default::default()
        };

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut written: u32 = 0;
        let status = unsafe {
            BCryptDecrypt(
                key.0,
                if ciphertext.is_empty() {
                    None
                } else {
                    Some(ciphertext)
                },
                Some(
                    (&mut auth_info as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO).cast::<c_void>(),
                ),
                None,
                if plaintext.is_empty() {
                    None
                } else {
                    Some(plaintext.as_mut_slice())
                },
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };
        if !status.is_ok() {
            return Err(format!(
                "BCryptDecrypt(AES-256-GCM) authentication failed: 0x{:08X}",
                status.0 as u32
            ));
        }
        plaintext.truncate(written as usize);
        Ok(plaintext)
    }
}

/// Encrypts `plaintext` with AES-256-GCM using native Windows CNG (`bcrypt.dll`).
#[cfg(windows)]
pub fn aes256_gcm_encrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    cng_gcm::encrypt(key_32, nonce_12, aad, plaintext)
}

#[cfg(not(windows))]
pub fn aes256_gcm_encrypt(
    _key_32: &[u8; 32],
    _nonce_12: &[u8; 12],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    Err("Windows CNG AES-256-GCM is only supported on Windows".into())
}

/// Decrypts and authenticates `ciphertext` + `tag_16` with AES-256-GCM using native Windows CNG.
#[cfg(windows)]
pub fn aes256_gcm_decrypt(
    key_32: &[u8; 32],
    nonce_12: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag_16: &[u8; 16],
) -> Result<Vec<u8>, String> {
    cng_gcm::decrypt(key_32, nonce_12, aad, ciphertext, tag_16)
}

#[cfg(not(windows))]
pub fn aes256_gcm_decrypt(
    _key_32: &[u8; 32],
    _nonce_12: &[u8; 12],
    _aad: &[u8],
    _ciphertext: &[u8],
    _tag_16: &[u8; 16],
) -> Result<Vec<u8>, String> {
    Err("Windows CNG AES-256-GCM is only supported on Windows".into())
}

struct ZeroizeKey([u8; AES256_KEY_LEN]);
impl Drop for ZeroizeKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
    }
}

struct ZeroizeVec(Vec<u8>);
impl Drop for ZeroizeVec {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// Seals a Clean-Room backup ZIP payload into a `CGBAK005` KEK+DEK envelope:
///
/// `Magic("CGBAK005") || u32_le(wrapped_dek_len) || dpapi_protect(dek_32, LocalMachine) || nonce_12 || tag_16 || ciphertext`
///
/// The entire prefix (`Magic || u32_le(wrapped_dek_len) || wrapped_dek`) is bound as AES-256-GCM
/// Additional Authenticated Data (AAD) so any header or wrapped-key tampering fails tag verification.
pub fn seal_cgbak_envelope(plaintext_zip: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext_zip.len() > MAX_CGBAK_PLAINTEXT_BYTES {
        return Err(format!(
            "backup payload {} bytes exceeds {MAX_CGBAK_PLAINTEXT_BYTES} byte limit",
            plaintext_zip.len()
        ));
    }

    let mut dek = ZeroizeKey([0u8; AES256_KEY_LEN]);
    random_bytes(&mut dek.0)?;

    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    random_bytes(&mut nonce)?;

    let wrapped_dek = protect_bytes(&dek.0, DpapiScope::LocalMachine)
        .map_err(|e| format!("DPAPI wrap DEK failed: {e}"))?;
    let wrapped_len = u32::try_from(wrapped_dek.len())
        .map_err(|_| "DPAPI wrapped DEK exceeds u32 length".to_string())?;

    let header_len = CGBAK_MAGIC.len() + 4 + wrapped_dek.len();
    let mut out =
        Vec::with_capacity(header_len + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN + plaintext_zip.len());
    out.extend_from_slice(CGBAK_MAGIC);
    out.extend_from_slice(&wrapped_len.to_le_bytes());
    out.extend_from_slice(&wrapped_dek);

    // Authenticate header bytes as GCM AAD.
    let (ciphertext, tag) = aes256_gcm_encrypt(&dek.0, &nonce, &out, plaintext_zip)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens and authenticates a `CGBAK005` KEK+DEK encrypted backup envelope back to its ZIP bytes.
pub fn open_cgbak_envelope(blob: &[u8]) -> Result<Vec<u8>, String> {
    let min_len = CGBAK_MAGIC.len() + 4 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;
    if blob.len() < min_len {
        return Err("CGBAK005 信封过短或已损坏".into());
    }
    if blob.len() > MAX_CGBAK_ENVELOPE_BYTES {
        return Err("CGBAK005 信封大小超过安全上限".into());
    }
    if &blob[..CGBAK_MAGIC.len()] != CGBAK_MAGIC {
        return Err("CGBAK005 魔数不匹配，非法的净室备份文件".into());
    }

    let wrapped_len = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    if wrapped_len == 0 || wrapped_len > MAX_SECRET_BYTES * 2 {
        return Err("CGBAK005 封装 DEK 长度非法".into());
    }

    let dek_start = CGBAK_MAGIC.len() + 4;
    let dek_end = dek_start
        .checked_add(wrapped_len)
        .ok_or_else(|| "CGBAK005 头部偏移溢出".to_string())?;
    let nonce_end = dek_end
        .checked_add(AES_GCM_NONCE_LEN)
        .ok_or_else(|| "CGBAK005 Nonce 偏移溢出".to_string())?;
    let tag_end = nonce_end
        .checked_add(AES_GCM_TAG_LEN)
        .ok_or_else(|| "CGBAK005 Tag 偏移溢出".to_string())?;
    if tag_end > blob.len() {
        return Err("CGBAK005 信封被截断".into());
    }

    let aad = &blob[..dek_end];
    let wrapped_dek = &blob[dek_start..dek_end];
    let dek_vec = ZeroizeVec(
        unprotect_bytes(wrapped_dek).map_err(|e| format!("DPAPI unwrap DEK failed: {e}"))?,
    );
    if dek_vec.0.len() != AES256_KEY_LEN {
        return Err(format!(
            "DPAPI 解包后的 DEK 长度异常：期望 {AES256_KEY_LEN}，实得 {}",
            dek_vec.0.len()
        ));
    }
    let mut dek = ZeroizeKey([0u8; AES256_KEY_LEN]);
    dek.0.copy_from_slice(&dek_vec.0);

    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(&blob[dek_end..nonce_end]);
    let mut tag = [0u8; AES_GCM_TAG_LEN];
    tag.copy_from_slice(&blob[nonce_end..tag_end]);
    let ciphertext = &blob[tag_end..];

    aes256_gcm_decrypt(&dek.0, &nonce, aad, ciphertext, &tag)
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

    #[cfg(windows)]
    #[test]
    fn windows_cng_aes256_gcm_roundtrip_and_tamper_rejection() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        random_bytes(&mut key).expect("rng key");
        random_bytes(&mut nonce).expect("rng nonce");

        // 1. Standard payload with AAD
        let aad = b"CGBAK005-header-aad";
        let msg = b"ClaudeGuard v5 clean-room encrypted ZIP payload test!".repeat(64);
        let (ct, tag) = aes256_gcm_encrypt(&key, &nonce, aad, &msg).expect("encrypt");
        assert_eq!(ct.len(), msg.len());
        assert_ne!(ct, msg);
        let pt = aes256_gcm_decrypt(&key, &nonce, aad, &ct, &tag).expect("decrypt");
        assert_eq!(pt, msg);

        // 2. Empty plaintext with empty AAD
        let (empty_ct, empty_tag) = aes256_gcm_encrypt(&key, &nonce, &[], &[]).expect("empty enc");
        assert!(empty_ct.is_empty());
        let empty_pt =
            aes256_gcm_decrypt(&key, &nonce, &[], &empty_ct, &empty_tag).expect("empty dec");
        assert!(empty_pt.is_empty());

        // 3. Ciphertext tamper must fail authentication
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(aes256_gcm_decrypt(&key, &nonce, aad, &bad_ct, &tag).is_err());

        // 4. Tag tamper must fail authentication
        let mut bad_tag = tag;
        bad_tag[15] ^= 0x80;
        assert!(aes256_gcm_decrypt(&key, &nonce, aad, &ct, &bad_tag).is_err());

        // 5. AAD mismatch must fail authentication
        assert!(aes256_gcm_decrypt(&key, &nonce, b"wrong-aad", &ct, &tag).is_err());

        // 6. Wrong key must fail authentication
        let mut bad_key = key;
        bad_key[0] ^= 0xFF;
        assert!(aes256_gcm_decrypt(&bad_key, &nonce, aad, &ct, &tag).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn cgbak005_envelope_roundtrip_and_tamper_rejection() {
        let payload = b"PK\x03\x04-simulated-large-cleanroom-zip-payload-".repeat(2048);
        let envelope = seal_cgbak_envelope(&payload).expect("seal CGBAK005");

        // Verify exact wire layout header: Magic("CGBAK005") || u32_le(wrapped_dek_len) || ...
        assert!(envelope.starts_with(CGBAK_MAGIC));
        let wrapped_len =
            u32::from_le_bytes([envelope[8], envelope[9], envelope[10], envelope[11]]) as usize;
        assert!(wrapped_len > 32);
        assert_eq!(
            envelope.len(),
            CGBAK_MAGIC.len()
                + 4
                + wrapped_len
                + AES_GCM_NONCE_LEN
                + AES_GCM_TAG_LEN
                + payload.len()
        );

        let opened = open_cgbak_envelope(&envelope).expect("open CGBAK005");
        assert_eq!(opened, payload);

        // Empty payload roundtrip
        let empty_env = seal_cgbak_envelope(&[]).expect("seal empty");
        assert!(open_cgbak_envelope(&empty_env)
            .expect("open empty")
            .is_empty());

        // Tamper checks: bad magic, truncated, mutated wrapped DEK, mutated nonce, mutated tag, mutated ciphertext
        let mut bad_magic = envelope.clone();
        bad_magic[0] = b'X';
        assert!(open_cgbak_envelope(&bad_magic).is_err());

        assert!(open_cgbak_envelope(&envelope[..20]).is_err());

        let mut bad_dek = envelope.clone();
        bad_dek[16] ^= 0x55;
        assert!(open_cgbak_envelope(&bad_dek).is_err());

        let nonce_off = CGBAK_MAGIC.len() + 4 + wrapped_len;
        let mut bad_nonce = envelope.clone();
        bad_nonce[nonce_off] ^= 0x01;
        assert!(open_cgbak_envelope(&bad_nonce).is_err());

        let tag_off = nonce_off + AES_GCM_NONCE_LEN;
        let mut bad_tag = envelope.clone();
        bad_tag[tag_off] ^= 0x01;
        assert!(open_cgbak_envelope(&bad_tag).is_err());

        let ct_off = tag_off + AES_GCM_TAG_LEN;
        let mut bad_ct = envelope.clone();
        bad_ct[ct_off] ^= 0x01;
        assert!(open_cgbak_envelope(&bad_ct).is_err());
    }
}
