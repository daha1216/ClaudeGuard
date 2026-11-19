//! Zero-external-zip-crate ZIP reader & writer backed by `flate2` + `crc32fast`.
//!
//! Used for:
//! - Extracting verified `version.dll` from `yuaotian/antigravity-proxy` GitHub release `.zip` assets.
//! - Building standard DEFLATE `.zip` diagnostic support bundles (fully redacted).

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

const LOCAL_FILE_SIG: u32 = 0x0403_4b50;
const CENTRAL_DIR_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

/// Maximum uncompressed size allowed when extracting a single member (32 MiB anti-zip-bomb guard).
pub const MAX_EXTRACT_BYTES: usize = 32 * 1024 * 1024;

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Extracts the first file whose path ends with `suffix_ci` (case-insensitive, e.g. `"version.dll"`)
/// from a ZIP archive (supports STORE method 0 and DEFLATE method 8, verifying CRC-32).
pub fn extract_file_from_zip(zip_bytes: &[u8], suffix_ci: &str) -> Result<(String, Vec<u8>), String> {
    let needle = suffix_ci.trim().replace('\\', "/").to_ascii_lowercase();
    if needle.is_empty() {
        return Err("ZIP 提取目标文件名为空".into());
    }
    if zip_bytes.len() < 22 {
        return Err("ZIP 文件过短或已损坏".into());
    }

    // Locate End of Central Directory (search backwards in last 64 KiB + 22 bytes).
    let search_start = zip_bytes.len().saturating_sub(65_557);
    let mut eocd_pos = None;
    for pos in (search_start..=zip_bytes.len() - 22).rev() {
        if read_u32_le(zip_bytes, pos) == Some(EOCD_SIG) {
            eocd_pos = Some(pos);
            break;
        }
    }
    let eocd = eocd_pos.ok_or_else(|| "无效 ZIP：未找到中央目录结束标记".to_string())?;
    let total_entries = read_u16_le(zip_bytes, eocd + 10).unwrap_or(0) as usize;
    let cd_size = read_u32_le(zip_bytes, eocd + 12).unwrap_or(0) as usize;
    let cd_offset = read_u32_le(zip_bytes, eocd + 16).unwrap_or(0) as usize;

    let cd_end = cd_offset
        .checked_add(cd_size)
        .filter(|&end| end <= zip_bytes.len())
        .ok_or_else(|| "无效 ZIP：中央目录越界".to_string())?;

    let mut cur = cd_offset;
    for _ in 0..total_entries {
        if cur + 46 > cd_end {
            break;
        }
        if read_u32_le(zip_bytes, cur) != Some(CENTRAL_DIR_SIG) {
            break;
        }
        let method = read_u16_le(zip_bytes, cur + 10).unwrap_or(u16::MAX);
        let expected_crc = read_u32_le(zip_bytes, cur + 16).unwrap_or(0);
        let comp_size = read_u32_le(zip_bytes, cur + 20).unwrap_or(0) as usize;
        let uncomp_size = read_u32_le(zip_bytes, cur + 24).unwrap_or(0) as usize;
        let name_len = read_u16_le(zip_bytes, cur + 28).unwrap_or(0) as usize;
        let extra_len = read_u16_le(zip_bytes, cur + 30).unwrap_or(0) as usize;
        let comment_len = read_u16_le(zip_bytes, cur + 32).unwrap_or(0) as usize;
        let local_off = read_u32_le(zip_bytes, cur + 42).unwrap_or(0) as usize;

        let name_end = cur + 46 + name_len;
        let Some(name_bytes) = zip_bytes.get(cur + 46..name_end) else {
            break;
        };
        let entry_name = String::from_utf8_lossy(name_bytes).replace('\\', "/");
        cur = name_end + extra_len + comment_len;

        let lower = entry_name.to_ascii_lowercase();
        let matches = lower == needle || lower.ends_with(&format!("/{needle}"));
        if !matches {
            continue;
        }
        if uncomp_size > MAX_EXTRACT_BYTES {
            return Err(format!("ZIP 条目 {entry_name} 超过大小上限，已拒绝"));
        }
        if local_off + 30 > zip_bytes.len()
            || read_u32_le(zip_bytes, local_off) != Some(LOCAL_FILE_SIG)
        {
            return Err(format!("ZIP 条目 {entry_name} 本地文件头损坏"));
        }
        let l_name_len = read_u16_le(zip_bytes, local_off + 26).unwrap_or(0) as usize;
        let l_extra_len = read_u16_le(zip_bytes, local_off + 28).unwrap_or(0) as usize;
        let data_start = local_off + 30 + l_name_len + l_extra_len;
        let data_end = data_start
            .checked_add(comp_size)
            .filter(|&e| e <= zip_bytes.len())
            .ok_or_else(|| format!("ZIP 条目 {entry_name} 数据区越界"))?;
        let comp_slice = &zip_bytes[data_start..data_end];

        let out = match method {
            0 => comp_slice.to_vec(),
            8 => {
                let mut dec = DeflateDecoder::new(comp_slice).take((MAX_EXTRACT_BYTES + 1) as u64);
                let mut buf = Vec::with_capacity(uncomp_size.min(MAX_EXTRACT_BYTES));
                dec.read_to_end(&mut buf)
                    .map_err(|e| format!("解压 ZIP 条目 {entry_name} 失败：{e}"))?;
                if buf.len() > MAX_EXTRACT_BYTES {
                    return Err(format!("解压后的 {entry_name} 超过大小上限"));
                }
                buf
            }
            other => {
                return Err(format!("不支持的 ZIP 压缩算法 ({other})：{entry_name}"));
            }
        };

        let actual_crc = crc32fast::hash(&out);
        if actual_crc != expected_crc {
            return Err(format!(
                "ZIP 条目 {entry_name} CRC32 校验不匹配（期望 {expected_crc:08x}，实得 {actual_crc:08x}）"
            ));
        }
        return Ok((entry_name, out));
    }

    Err(format!("ZIP 归档中未找到目标文件：{suffix_ci}"))
}

/// Builds a standard DEFLATE `.zip` archive in memory from `(filename, content)` pairs.
pub fn build_zip_archive(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for &(raw_name, data) in entries {
        let name = raw_name.trim_start_matches(['/', '\\']).replace('\\', "/");
        let name_bytes = name.as_bytes();
        let crc = crc32fast::hash(data);

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data)
            .map_err(|e| format!("压缩诊断文件 {name} 失败：{e}"))?;
        let compressed = enc
            .finish()
            .map_err(|e| format!("完成压缩 {name} 失败：{e}"))?;

        let (method, payload): (u16, &[u8]) = if compressed.len() < data.len() {
            (8, &compressed)
        } else {
            (0, data)
        };

        let local_offset = out.len() as u32;
        // Local file header
        out.extend_from_slice(&LOCAL_FILE_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 filename flag
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(payload);

        // Central directory header
        central.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory record
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk num
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_build_and_extract_roundtrips_deflate_and_store_with_crc() {
        let big_payload = b"MZ-antigravity-proxy-config.json-".repeat(256);
        let small_payload = b"ok";
        let archive = build_zip_archive(&[
            ("nested/version.dll", &big_payload),
            ("readme.txt", small_payload),
        ])
        .expect("build zip");

        let (name, extracted) =
            extract_file_from_zip(&archive, "version.dll").expect("extract dll");
        assert_eq!(name, "nested/version.dll");
        assert_eq!(extracted, big_payload);

        let (rname, rbytes) = extract_file_from_zip(&archive, "README.TXT").expect("extract txt");
        assert_eq!(rname, "readme.txt");
        assert_eq!(rbytes, small_payload);

        assert!(extract_file_from_zip(&archive, "missing.dll").is_err());
    }
}
