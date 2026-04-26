//! Environment for subprocesses of the GUI app: launchd gives a tiny PATH, so tools like
//! Homebrew `pip`/`python3` are missing unless we prepend standard locations.

use std::ffi::OsString;
use std::path::Path;

/// PATH merged with typical macOS/Linux locations (Homebrew, /usr/local).
pub fn merged_path() -> OsString {
    #[cfg(unix)]
    {
        let prepend: &str = if cfg!(target_os = "macos") {
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        } else {
            "/usr/local/bin:/usr/bin:/bin"
        };
        match std::env::var_os("PATH") {
            Some(p) => {
                let mut s = OsString::from(prepend);
                s.push(":");
                s.push(p);
                s
            }
            None => OsString::from(prepend),
        }
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("PATH").unwrap_or_default()
    }
}

/// macOS GUI may inherit a broken `DOCKER_HOST`; remove so the CLI uses context defaults.
pub fn clear_stale_docker_host() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(dh) = std::env::var("DOCKER_HOST") {
            if dh.trim().is_empty() {
                return true;
            }
            if let Some(rest) = dh.strip_prefix("unix://") {
                return !Path::new(rest.trim()).exists();
            }
        }
    }
    false
}
