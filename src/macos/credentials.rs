//! AES-GCM credentials; the encryption key stays in the user's login Keychain.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use std::io::Read;
const SERVICE: &str = "com.daha.claudeguard.feishu";
const PREFIX: &[u8] = b"macos-aesgcm-v1:";

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| "无法生成加密随机数")?;
    Ok(bytes)
}

#[cfg(not(test))]
fn key() -> Result<[u8; 32], String> {
    use security_framework::passwords::{get_generic_password, set_generic_password};
    use sha2::{Digest, Sha256};
    // Serialize first-use creation. Distinct isolated profiles never share keys.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().map_err(|_| "凭据锁不可用")?;
    let account = format!(
        "{:x}",
        Sha256::digest(crate::macos::data_dir().to_string_lossy().as_bytes())
    );
    match get_generic_password(SERVICE, &account) {
        Ok(bytes) => bytes.try_into().map_err(|_| "钥匙串密钥格式无效".into()),
        Err(e) if e.code() == -25300 => {
            let key = random()?;
            set_generic_password(SERVICE, &account, &key)
                .map_err(|_| "无法将密钥写入登录钥匙串，凭据未保存")?;
            Ok(key)
        }
        Err(_) => Err("无法访问登录钥匙串；请解锁后重试，未覆盖原密钥".into()),
    }
}
// Shared Feishu tests use a synthetic key; they never alter the real login Keychain.
#[cfg(test)]
fn key() -> Result<[u8; 32], String> {
    Ok([42; 32])
}

pub fn crypt(bytes: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    if bytes.len() > 65_536 {
        return Err("凭据长度无效".into());
    }
    if decrypt && !bytes.starts_with(PREFIX) {
        return Err("不是 macOS 凭据密文；不能直接迁移 Windows DPAPI 凭据，请重新填写".into());
    }
    crypt_with_key(bytes, decrypt, &key()?)
}
fn crypt_with_key(bytes: &[u8], decrypt: bool, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "凭据密钥无效")?;
    if decrypt {
        let encrypted = bytes
            .strip_prefix(PREFIX)
            .filter(|b| b.len() >= 12 + 16)
            .ok_or("密文格式无效")?;
        cipher
            .decrypt(
                Nonce::from_slice(&encrypted[..12]),
                Payload {
                    msg: &encrypted[12..],
                    aad: SERVICE.as_bytes(),
                },
            )
            .map_err(|_| "凭据解密失败，密钥不匹配或数据损坏".into())
    } else {
        let nonce = random::<12>()?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: bytes,
                    aad: SERVICE.as_bytes(),
                },
            )
            .map_err(|_| "凭据加密失败")?;
        Ok([PREFIX, nonce.as_slice(), encrypted.as_slice()].concat())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_tampering_and_wrong_key() {
        let encrypted = crypt("test-only-中文".as_bytes(), false).unwrap();
        assert_eq!(
            crypt(&encrypted, true).unwrap(),
            "test-only-中文".as_bytes()
        );
        assert!(crypt_with_key(&encrypted, true, &[7; 32]).is_err());
        let mut damaged = encrypted.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(crypt(&damaged, true).is_err());
        assert_ne!(
            encrypted,
            crypt("test-only-中文".as_bytes(), false).unwrap()
        );
        for data in [b"Windows ciphertext".as_slice(), PREFIX, b""] {
            assert!(crypt(data, true).is_err());
        }
        assert!(crypt(&vec![0; 65_537], false).is_err());
    }
    #[test]
    #[ignore = "requires unlocked login Keychain; creates and removes one synthetic item"]
    fn keychain_roundtrip() {
        use security_framework::passwords::{
            delete_generic_password, get_generic_password, set_generic_password,
        };
        let account: String = random::<32>()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let original = random::<32>().unwrap();
        set_generic_password(SERVICE, &account, &original).unwrap();
        let loaded: [u8; 32] = get_generic_password(SERVICE, &account)
            .unwrap()
            .try_into()
            .unwrap();
        // Remove the synthetic item before any assertion can fail.
        delete_generic_password(SERVICE, &account).unwrap();
        let encrypted = crypt_with_key(b"synthetic only", false, &loaded).unwrap();
        assert_eq!(
            crypt_with_key(&encrypted, true, &original).unwrap(),
            b"synthetic only"
        );
    }
}
