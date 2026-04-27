use crate::gui_spawn_env::merged_path;
use crate::settings::AppSettings;
use dunce::canonicalize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn roots_as_pathbufs(settings: &AppSettings) -> Vec<PathBuf> {
    settings
        .allowlisted_roots
        .iter()
        .filter_map(|s| {
            let p = PathBuf::from(s);
            if p.as_os_str().is_empty() {
                None
            } else {
                Some(p)
            }
        })
        .collect()
}

/// Workspace root plus user allowlisted directories (deduped by canonical path).
fn combined_roots(settings: &AppSettings) -> Result<Vec<PathBuf>, String> {
    let ws = crate::settings::resolve_workspace_dir(settings)?;
    std::fs::create_dir_all(&ws).map_err(|e| format!("workspace: {e}"))?;
    let ws_canon = canonicalize(&ws).map_err(|e| format!("workspace: {e}"))?;

    let mut roots: Vec<PathBuf> = vec![ws_canon];

    for p in roots_as_pathbufs(settings) {
        let c = canonicalize(&p).map_err(|e| {
            format!(
                "allowlisted root {} is not accessible: {e}",
                p.display()
            )
        })?;
        if !roots.iter().any(|r| r == &c) {
            roots.push(c);
        }
    }

    Ok(roots)
}

/// Returns canonical path if it lies under the workspace or another allowlisted root.
pub fn resolve_under_roots(path: &Path, settings: &AppSettings) -> Result<PathBuf, String> {
    let roots = combined_roots(settings)?;
    if roots.is_empty() {
        return Err(
            "No accessible workspace or allowlisted roots. Use Settings → Workspace to prepare a folder."
                .into(),
        );
    }

    if path.as_os_str().is_empty() {
        return Err(
            "Empty path — the UI may have received tool arguments in the wrong shape. Ensure path is a non-empty string."
                .into(),
        );
    }

    let candidate = canonicalize(path).map_err(|e| {
        format!(
            "Could not resolve path \"{}\" ({e}). Check it exists on disk, is not an iCloud placeholder, and matches the workspace path exactly.",
            path.display()
        )
    })?;

    for root in &roots {
        let root_canon = canonicalize(root).map_err(|e| {
            format!(
                "allowlisted root {} is not accessible: {e}",
                root.display()
            )
        })?;
        if candidate.starts_with(&root_canon) {
            return Ok(candidate);
        }
    }

    Err(format!(
        "Path {} is not under any allowlisted root",
        candidate.display()
    ))
}

/// Resolves a path for **writing** a UTF-8 file: same allowlist as reads. Creates missing
/// parent directories. `path` must be absolute. If the file already exists, behaves like
/// [resolve_under_roots] on that file.
pub fn resolve_path_for_write(path: &Path, settings: &AppSettings) -> Result<PathBuf, String> {
    let p = if path.is_absolute() {
        path.to_path_buf()
    } else {
        return Err(
            "Path must be absolute — build it from **workspaceRoot** in get_environment (or a subpath under it)."
                .into(),
        );
    };
    if p.is_dir() {
        return Err("Path points to a directory. Provide a file path (not a folder).".into());
    }
    if p.is_file() {
        return resolve_under_roots(&p, settings);
    }
    // New file: walk up until an existing path is found, then rejoin.
    let mut cur = p.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !cur.exists() {
        let Some(name) = cur.file_name() else {
            return Err("Invalid file path (no file name).".into());
        };
        tail.push(name.to_os_string());
        cur = cur
            .parent()
            .ok_or_else(|| "Path has no parent; cannot create file.".to_string())?;
    }
    if !cur.is_dir() {
        return Err(
            "A path component exists but is a file, not a directory. Pick a different name or path."
                .into(),
        );
    }
    let base = resolve_under_roots(&cur.to_path_buf(), settings)?;
    let mut out = base;
    for comp in tail.iter().rev() {
        out = out.join(comp);
    }
    for c in out.components() {
        if c == std::path::Component::ParentDir {
            return Err("Path must not contain '..'".into());
        }
    }
    Ok(out)
}

pub fn is_bare_executable_name(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\\')
}

/// First match on a merged `PATH` (not the bare shell search). Used to suggest a full path when a program is not yet allowed.
pub fn lookup_bare_in_path(name: &str) -> Option<PathBuf> {
    if !is_bare_executable_name(name) {
        return None;
    }
    let path_os = merged_path();
    let path_str = path_os.to_string_lossy();
    let sep = if cfg!(windows) { ';' } else { ':' };
    for dir in path_str.split(sep) {
        let d = dir.trim();
        if d.is_empty() {
            continue;
        }
        let try_paths: Vec<PathBuf> = {
            let first = Path::new(d).join(name);
            #[cfg(windows)]
            {
                vec![first, Path::new(d).join(format!("{name}.exe"))]
            }
            #[cfg(not(windows))]
            {
                vec![first]
            }
        };
        for candidate in try_paths {
            if candidate.is_file() {
                if let Ok(c) = dunce::canonicalize(&candidate) {
                    return Some(c);
                }
            }
        }
    }
    None
}

/// Standard install locations for tools that are almost always symlinked here when installed
/// (Docker Desktop, Homebrew). Used only when the user passes a bare name like `docker` and
/// has not listed it under Allowed executables — avoids requiring `which docker` for common setups.
fn well_known_executable_paths(requested: &str) -> &'static [&'static str] {
    match requested.to_lowercase().as_str() {
        "docker" => &[
            "/opt/homebrew/bin/docker",
            "/usr/local/bin/docker",
            "/usr/bin/docker",
        ],
        "docker-compose" => &[
            "/opt/homebrew/bin/docker-compose",
            "/usr/local/bin/docker-compose",
            "/usr/bin/docker-compose",
        ],
        _ => &[],
    }
}

fn try_resolve_well_known_bare(program: &str) -> Option<PathBuf> {
    if !is_bare_executable_name(program) {
        return None;
    }
    for p in well_known_executable_paths(program) {
        let pb = Path::new(p);
        if pb.is_file() {
            if let Ok(c) = canonicalize(pb) {
                return Some(c);
            }
        }
    }
    None
}

/// True if `allowed_path`'s file name is the same as `requested`, or common aliases (e.g. python ↔ python3).
fn basename_matches_requested(allowed_path: &Path, requested: &str) -> bool {
    let Some(fname) = allowed_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let f = fname.to_lowercase();
    let r = requested.to_lowercase();
    if f == r {
        return true;
    }
    if r == "python" && (f == "python3" || f == "python2" || f == "python") {
        return true;
    }
    if r == "python3" && (f == "python3" || f == "python") {
        return true;
    }
    if r == "node" && (f == "node" || f == "nodejs") {
        return true;
    }
    if r == "docker-compose" && (f == "docker-compose" || f == "docker") {
        return true;
    }
    if r == "docker" && (f == "docker" || f == "com.docker.cli") {
        return true;
    }
    false
}

/// Program must be under an allowlisted root, or listed in `allowed_executables`.
/// A **bare name** like `python3` is resolved by matching the **basename** of an allowed path
/// (the app does not use your shell `PATH`).
/// `session` is an optional, extra set of full canonical paths approved for this app session
/// (one-shot; see **session_allow_for_program** in the Tauri app).
pub fn resolve_program_path(
    program: &Path,
    settings: &AppSettings,
    session: Option<&HashSet<String>>,
) -> Result<PathBuf, String> {
    let prog_str = program.to_string_lossy().to_string();

    if let Some(session) = session {
        if let Ok(canon) = dunce::canonicalize(program) {
            let k = canon.to_string_lossy().into_owned();
            if session.contains(&k) && canon.is_file() {
                return Ok(canon);
            }
        }
    }

    for allowed in &settings.allowed_executables {
        if allowed.is_empty() {
            continue;
        }
        let allowed_path = Path::new(allowed);
        if let Ok(canonical_allowed) = canonicalize(allowed_path) {
            if let Ok(canonical_prog) = canonicalize(program) {
                if canonical_allowed == canonical_prog {
                    return Ok(canonical_prog);
                }
            }
        }
        if *allowed == prog_str {
            return canonicalize(allowed_path).map_err(|e| {
                format!("executable {} not found: {e}", allowed_path.display())
            });
        }
    }

    if is_bare_executable_name(&prog_str) {
        for allowed in &settings.allowed_executables {
            if allowed.is_empty() {
                continue;
            }
            let allowed_path = Path::new(allowed);
            if basename_matches_requested(allowed_path, &prog_str) {
                return canonicalize(allowed_path).map_err(|e| {
                    format!(
                        "allowed executable {} could not be accessed: {e}",
                        allowed_path.display()
                    )
                });
            }
        }
        if let Some(p) = try_resolve_well_known_bare(&prog_str) {
            return Ok(p);
        }
        if let Some(session) = session {
            for s in session.iter() {
                let p = Path::new(s);
                if basename_matches_requested(p, &prog_str) {
                    if let Ok(c) = dunce::canonicalize(p) {
                        if c.is_file() {
                            return Ok(c);
                        }
                    }
                }
            }
        }
        return Err(format!(
            "Program '{prog_str}' is not an absolute path and does not match any allowed executable basename. \
Add the full path in Settings (run `which {prog_str}` in Terminal), one path per line, then retry. \
Example: /usr/bin/python3"
        ));
    }

    resolve_under_roots(program, settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn rejects_path_outside_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("proj");
        fs::create_dir_all(&inner).unwrap();
        let outside = tmp.path().join("other");
        fs::create_dir_all(&outside).unwrap();

        let settings = AppSettings {
            allowlisted_roots: vec![inner.to_string_lossy().to_string()],
            ..AppSettings::default()
        };

        let file_inside = inner.join("a.txt");
        fs::File::create(&file_inside).unwrap().write_all(b"x").unwrap();
        assert!(resolve_under_roots(&file_inside, &settings).is_ok());

        let file_outside = outside.join("b.txt");
        fs::File::create(&file_outside).unwrap().write_all(b"y").unwrap();
        assert!(resolve_under_roots(&file_outside, &settings).is_err());
    }

    #[test]
    fn bare_python3_resolves_via_allowed_basename() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_py = tmp.path().join("python3");
        fs::write(&fake_py, "#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&fake_py).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&fake_py, p).unwrap();
        }
        let settings = AppSettings {
            allowed_executables: vec![fake_py.to_string_lossy().to_string()],
            ..AppSettings::default()
        };
        let p = Path::new("python3");
        let got = resolve_program_path(p, &settings, None).unwrap();
        assert!(got.ends_with("python3"));
    }

    #[test]
    fn resolve_path_for_write_new_file_under_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("ws");
        fs::create_dir_all(&inner).unwrap();
        let settings = AppSettings {
            allowlisted_roots: vec![inner.to_string_lossy().to_string()],
            ..AppSettings::default()
        };
        let new_f = inner.join("deep").join("new.txt");
        let got = resolve_path_for_write(&new_f, &settings).unwrap();
        assert!(got.ends_with("new.txt"), "got {}", got.display());
    }
}
