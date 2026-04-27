use crate::paths::{is_bare_executable_name, lookup_bare_in_path};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;
use tauri::State;

/// Ephemeral per-run allow list (in-memory). Clears when the app quits.
pub struct SessionAllowlist {
    pub paths: Mutex<HashSet<String>>,
}

impl Default for SessionAllowlist {
    fn default() -> Self {
        Self {
            paths: Mutex::new(HashSet::new()),
        }
    }
}

fn insert_canonical(state: &SessionAllowlist, path: &Path) -> Result<String, String> {
    if path.as_os_str().is_empty() {
        return Err("empty path".into());
    }
    let c = dunce::canonicalize(path).map_err(|e| format!("invalid path: {e}"))?;
    if !c.is_file() {
        return Err(format!("not a file: {}", c.display()));
    }
    let s = c.to_string_lossy().into_owned();
    state
        .paths
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .insert(s.clone());
    Ok(s)
}

/// Add one canonical executable path for the lifetime of the app. Used after user chooses **allow once** on a blocked run.
#[tauri::command]
pub fn session_allow_for_program(
    state: State<SessionAllowlist>,
    program: String,
    suggested_path: Option<String>,
) -> Result<String, String> {
    if let Some(s) = suggested_path
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        return insert_canonical(&*state, Path::new(s));
    }

    let program = program.trim();
    if program.is_empty() {
        return Err("empty program name".into());
    }

    if !is_bare_executable_name(program) {
        return insert_canonical(&*state, Path::new(program));
    }

    if let Some(p) = lookup_bare_in_path(program) {
        return insert_canonical(&*state, p.as_path());
    }

    Err("Could not find that name on PATH. Add the full path in Settings (Allowed executables) or use the suggested path from the denied run.".into())
}
