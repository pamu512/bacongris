//! Atomic writes and rolling backups for JSON and text files (Issue 10).
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BACKUPS: usize = 3;

fn backup_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Write `content` to `path` atomically, keeping up to `MAX_BACKUPS` prior versions as
/// `path.backup.<timestamp>`, pruning oldest.
pub fn write_with_backup(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create_dir_all: {e}"))?;
    }
    if path.exists() {
        let prev = fs::read_to_string(path).map_err(|e| format!("read for backup: {e}"))?;
        let base = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or("path file_name")?;
        let backup_name = format!("{base}.backup.{}", backup_ms());
        let backup_path = path.with_file_name(backup_name);
        fs::write(&backup_path, prev).map_err(|e| format!("write backup: {e}"))?;
        prune_backups_of(path)?;
    }
    let mut tmp = path.to_path_buf();
    tmp.as_mut_os_string().push(".write_tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("temp: {e}"))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("temp write: {e}"))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

/// Remove older `.backup.*` files for the same base filename, keep newest `MAX_BACKUPS`.
fn prune_backups_of(original: &Path) -> Result<(), String> {
    let Some(parent) = original.parent() else {
        return Ok(());
    };
    let base = original
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or("stem")?;
    let prefix = format!("{base}.backup.");
    let mut backups: Vec<_> = fs::read_dir(parent)
        .map_err(|e| format!("read_dir: {e}"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name();
            let s = n.to_str()?;
            s.starts_with(&prefix).then_some((e.path(), e.metadata().ok()?.modified().ok()?))
        })
        .collect();
    backups.sort_by_key(|(_, t)| *t);
    if backups.len() > MAX_BACKUPS {
        for (p, _) in backups.iter().take(backups.len() - MAX_BACKUPS) {
            let _ = fs::remove_file(p);
        }
    }
    Ok(())
}
