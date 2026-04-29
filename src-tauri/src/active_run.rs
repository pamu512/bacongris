//! Tracks the current `run_command` (or `docker run`) child PID so the UI can cancel it.
use std::sync::Mutex;
use tauri::AppHandle;
use tauri::Manager;
use tauri::State;

/// Platform-specific kill; returns Ok if no error invoking the OS.
pub fn kill_process_tree(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Ok(());
    }
    #[cfg(unix)]
    {
        if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
            // Fallback to SIGKILL if TERM is ignored
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
        return Ok(());
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F", "/T"])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("taskkill exited: {status}"));
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        Err("killing process not supported on this target".to_string())
    }
}

/// Shared with [`crate::executor::run_command`].
pub struct ActiveRunState {
    pub current_pid: Mutex<Option<u32>>,
}

impl Default for ActiveRunState {
    fn default() -> Self {
        Self {
            current_pid: Mutex::new(None),
        }
    }
}

pub fn set_active_pid(state: &ActiveRunState, pid: u32) {
    if let Ok(mut g) = state.current_pid.lock() {
        *g = Some(pid);
    }
}

pub fn clear_active_pid(state: &ActiveRunState) {
    if let Ok(mut g) = state.current_pid.lock() {
        *g = None;
    }
}

/// Call after registering a PID: clears our slot when the `run_command` future leaves scope.
pub struct ClearActiveOnDrop {
    app: AppHandle,
}

impl ClearActiveOnDrop {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl Drop for ClearActiveOnDrop {
    fn drop(&mut self) {
        let s = self.app.state::<ActiveRunState>();
        clear_active_pid(&*s);
    }
}

/// Best-effort stop of a running command started by the agent (e.g. user hit Cancel).
#[tauri::command]
pub fn cancel_active_run(state: State<'_, ActiveRunState>) -> Result<String, String> {
    let pid = state
        .current_pid
        .lock()
        .map_err(|e| e.to_string())?
        .take();
    if let Some(p) = pid {
        kill_process_tree(p)?;
        Ok(format!("Sent stop signal to process (pid {p})"))
    } else {
        Ok("No active command to cancel".into())
    }
}
