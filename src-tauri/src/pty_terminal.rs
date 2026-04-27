//! Integrated terminal (real PTY) — Cursor-style shell in the app.

use crate::gui_spawn_env::{clear_stale_docker_host, merged_path};
use crate::app_data::AppStore;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::{AppHandle, Emitter, Manager, State};

const DEFAULT_PTY_COLS: u16 = 120;
const DEFAULT_PTY_ROWS: u16 = 32;

const EVENT_DATA: &str = "pty-data";
const EVENT_EXIT: &str = "pty-exit";

struct TermInner {
    master: Option<Box<dyn MasterPty + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
}

impl Default for TermInner {
    fn default() -> Self {
        Self {
            master: None,
            writer: None,
            child: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct TerminalState(Arc<Mutex<TermInner>>);

fn augment_pty_command(cmd: &mut CommandBuilder) {
    if let Some(home) = dirs::home_dir() {
        cmd.env("HOME", home);
    }
    if std::env::var_os("TMPDIR").is_none() {
        let tmp = std::env::temp_dir();
        if !tmp.as_os_str().is_empty() {
            cmd.env("TMPDIR", tmp);
        }
    }
    #[cfg(unix)]
    {
        cmd.env("PATH", merged_path());
        // Helps Python scripts that print before input() show lines immediately in the PTY.
        if std::env::var_os("PYTHONUNBUFFERED").is_none() {
            cmd.env("PYTHONUNBUFFERED", "1");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if clear_stale_docker_host() {
            cmd.env_remove("DOCKER_HOST");
        }
    }
}

fn shell_command() -> CommandBuilder {
    // macOS GUI apps often inherit SHELL=/bin/bash → bash 3.2 without Homebrew/pyenv on PATH.
    // Match Terminal.app: login zsh loads ~/.zprofile and ~/.zshrc.
    #[cfg(all(unix, target_os = "macos"))]
    {
        let mut c = CommandBuilder::new("/bin/zsh");
        c.args(["-il"]);
        c.env("SHELL", "/bin/zsh");
        augment_pty_command(&mut c);
        c
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let sh = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
        let mut c = CommandBuilder::new(&sh);
        if sh.contains("zsh") {
            c.arg("-il");
        } else if sh.contains("bash") {
            c.arg("-il");
        }
        augment_pty_command(&mut c);
        c
    }
    #[cfg(windows)]
    {
        let mut c = CommandBuilder::new(
            std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into()),
        );
        c.arg("/k");
        augment_pty_command(&mut c);
        c
    }
}

fn kill_session(inner: &mut TermInner) {
    if let Some(mut c) = inner.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    inner.writer = None;
    inner.master = None;
}

/// Starts a new PTY shell into `inner` (must be empty). Caller may have called `kill_session` first.
fn pty_start_into_inner(
    app: &AppHandle,
    inner: &mut TermInner,
    cwd: Option<String>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    if inner.writer.is_some() {
        return Err("internal: pty start while session active".into());
    }

    let cols = cols.max(40);
    let rows = rows.max(10);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("openpty: {e}"))?;

    let mut cmd = shell_command();
    if let Some(ref c) = cwd {
        let t = c.trim();
        if !t.is_empty() {
            cmd.cwd(t);
        }
    }

    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("spawn shell: {e}"))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("pty reader: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("pty writer: {e}"))?;
    let master = pair.master;

    let app_emit = app.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let enc = B64.encode(&buf[..n]);
                    let _ = app_emit.emit(EVENT_DATA, enc);
                }
                Err(_) => break,
            }
        }
        let _ = app_emit.emit(EVENT_EXIT, ());
    });

    inner.master = Some(master);
    inner.writer = Some(writer);
    inner.child = Some(child);
    Ok(())
}

fn default_terminal_cwd(app: &AppHandle, cwd: Option<String>) -> Result<String, String> {
    if let Some(ref c) = cwd {
        let t = c.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let store = app.state::<AppStore>();
    let w = store.effective_workspace_path(app)?;
    std::fs::create_dir_all(&w).map_err(|e| format!("workspace: {e}"))?;
    Ok(w.to_string_lossy().into_owned())
}

#[tauri::command]
pub fn terminal_spawn(
    app: AppHandle,
    cwd: Option<String>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let state: tauri::State<'_, TerminalState> = app.state();
    {
        let mut inner = state.0.lock().map_err(|e| e.to_string())?;
        kill_session(&mut *inner);
    }

    let effective_cwd = default_terminal_cwd(&app, cwd)?;

    let mut inner = state.0.lock().map_err(|e| e.to_string())?;
    pty_start_into_inner(
        &app,
        &mut *inner,
        Some(effective_cwd),
        cols,
        rows,
    )?;
    Ok(())
}

/// Returns true if a live PTY session is connected (e.g. started by the agent or an earlier UI attach).
/// The UI can attach listeners without `terminal_kill`+`terminal_spawn` so the agent is not cut off.
#[tauri::command]
pub fn terminal_is_active(state: State<'_, TerminalState>) -> bool {
    match state.0.lock() {
        Ok(inner) => inner.writer.is_some(),
        Err(_) => false,
    }
}

/// Ensure a shell session exists, then write bytes. Used by the agent to drive the in-app
/// terminal without a manual click. Spawns with default 120×32 if there is no session.
#[tauri::command]
pub fn terminal_ensure_write(app: AppHandle, data: String, cwd: Option<String>) -> Result<(), String> {
    if data.is_empty() {
        return Err("empty data".into());
    }
    let state: tauri::State<'_, TerminalState> = app.state();
    {
        let mut inner = state.0.lock().map_err(|e| e.to_string())?;
        if inner.writer.is_none() {
            let effective_cwd = default_terminal_cwd(&app, cwd)?;
            pty_start_into_inner(
                &app,
                &mut *inner,
                Some(effective_cwd),
                DEFAULT_PTY_COLS,
                DEFAULT_PTY_ROWS,
            )?;
        }
    }
    let mut inner = state.0.lock().map_err(|e| e.to_string())?;
    let w = inner
        .writer
        .as_mut()
        .ok_or_else(|| "terminal: failed to open writer".to_string())?;
    w.write_all(data.as_bytes())
        .map_err(|e| format!("pty write: {e}"))?;
    let _ = w.flush();
    Ok(())
}

#[tauri::command]
pub fn terminal_write(app: AppHandle, data: String) -> Result<(), String> {
    let state: tauri::State<'_, TerminalState> = app.state();
    let mut inner = state.0.lock().map_err(|e| e.to_string())?;
    let w = inner
        .writer
        .as_mut()
        .ok_or_else(|| "No terminal session — click New terminal.".to_string())?;
    w.write_all(data.as_bytes())
        .map_err(|e| format!("pty write: {e}"))?;
    let _ = w.flush();
    Ok(())
}

#[tauri::command]
pub fn terminal_resize(app: AppHandle, cols: u16, rows: u16) -> Result<(), String> {
    let state: tauri::State<'_, TerminalState> = app.state();
    let inner = state.0.lock().map_err(|e| e.to_string())?;
    let m = inner
        .master
        .as_ref()
        .ok_or_else(|| "No terminal session".to_string())?;
    let cols = cols.max(40);
    let rows = rows.max(10);
    m.resize(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })
    .map_err(|e| format!("pty resize: {e}"))
}

#[tauri::command]
pub fn terminal_kill(app: AppHandle) -> Result<(), String> {
    let state: tauri::State<'_, TerminalState> = app.state();
    let mut inner = state.0.lock().map_err(|e| e.to_string())?;
    kill_session(&mut inner);
    Ok(())
}
