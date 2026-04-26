use crate::settings::AppSettings;
use dunce::canonicalize;
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

fn is_bare_executable_name(s: &str) -> bool {
    !s.is_empty() && !s.contains('/') && !s.contains('\\')
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
pub fn resolve_program_path(program: &Path, settings: &AppSettings) -> Result<PathBuf, String> {
    let prog_str = program.to_string_lossy().to_string();

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
        let got = resolve_program_path(p, &settings).unwrap();
        assert!(got.ends_with("python3"));
    }
}
