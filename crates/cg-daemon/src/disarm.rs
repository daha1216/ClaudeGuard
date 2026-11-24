//! Persistent `disarmed` intent marker.
//!
//! Used by Flow B (`DisarmAndRestoreFlowB`) and offline `--restore` so a subsequent
//! daemon/service restart honors the explicit user disarm and does not re-apply isolation
//! until the user explicitly invokes `Rearm`.

use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub const DISARM_FILE: &str = "disarmed";

pub fn disarm_path(dir: &Path) -> PathBuf {
    dir.join(DISARM_FILE)
}

/// Reads the disarm reason if the persistent disarm marker is present.
pub fn read_disarmed(dir: &Path) -> Result<Option<String>, String> {
    let path = disarm_path(dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "failed to read disarm marker {}: {err}",
            path.display()
        )),
    }
}

/// Atomically writes and fsyncs the persistent disarm marker.
pub fn mark_disarmed(dir: &Path, reason: &str) -> Result<(), String> {
    crate::journal::ensure_secure_data_dir(dir)?;
    let path = disarm_path(dir);
    let mut tmp = NamedTempFile::new_in(dir).map_err(|e| {
        format!(
            "failed to create temp disarm file in {}: {e}",
            dir.display()
        )
    })?;
    tmp.write_all(reason.as_bytes())
        .map_err(|e| format!("failed to write disarm marker: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("failed to sync disarm marker: {e}"))?;
    tmp.persist(&path).map_err(|e| {
        format!(
            "failed to persist disarm marker {}: {}",
            path.display(),
            e.error
        )
    })?;
    Ok(())
}

/// Removes the persistent disarm marker (idempotent when absent).
pub fn clear_disarmed(dir: &Path) -> Result<(), String> {
    let path = disarm_path(dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "failed to clear disarm marker {}: {err}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disarm_marker_roundtrip_and_idempotent_clear() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_disarmed(dir.path()).unwrap(), None);

        mark_disarmed(dir.path(), "cli --restore").unwrap();
        assert_eq!(
            read_disarmed(dir.path()).unwrap().as_deref(),
            Some("cli --restore")
        );

        clear_disarmed(dir.path()).unwrap();
        assert_eq!(read_disarmed(dir.path()).unwrap(), None);
        clear_disarmed(dir.path()).unwrap();
    }
}
