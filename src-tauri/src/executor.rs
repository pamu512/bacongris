use crate::audit::append_audit;
use crate::gui_spawn_env::{clear_stale_docker_host, merged_path};
use crate::paths::{resolve_program_path, resolve_under_roots};
use crate::settings::load_settings;
use crate::workspace::workspace_info_from_settings;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// GUI‑launched macOS apps often inherit a sparse or stale environment (e.g. `DOCKER_HOST`
/// pointing at a dead `unix://` path from an old tool). Login shells fix this automatically;
/// align spawned tools with a typical interactive session so `docker` and similar CLIs work.
fn augment_command_env(cmd: &mut Command) {
    if let Some(home) = dirs::home_dir() {
        cmd.env("HOME", &home);
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
        #[cfg(target_os = "macos")]
        {
            if clear_stale_docker_host() {
                cmd.env_remove("DOCKER_HOST");
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
}

async fn read_limited<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    max: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut truncated = false;
    loop {
        if buf.len() >= max {
            truncated = true;
            break;
        }
        let to_read = (max - buf.len()).min(chunk.len());
        let n = reader.read(&mut chunk[..to_read]).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= max {
            truncated = true;
            break;
        }
    }
    Ok((buf, truncated))
}

fn lossy_string(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tauri::command]
pub async fn run_command(
    app: tauri::AppHandle,
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
) -> Result<CommandResult, String> {
    let settings = load_settings(&app)?;
    let program = program.trim().to_string();
    if program.is_empty() {
        return Err("program is empty".into());
    }
    let program_path = PathBuf::from(&program);
    let prog_canon = resolve_program_path(&program_path, &settings)?;

    let cwd_canon: PathBuf = match &cwd {
        None => prog_canon
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "program has no parent directory for default cwd".to_string())?,
        Some(c) => {
            let c = c.trim();
            if c.is_empty() {
                return Err("cwd is empty when set".into());
            }
            let p = Path::new(c);
            resolve_under_roots(p, &settings)?
        }
    };

    let max = settings.max_output_bytes.max(1024);
    let dur = Duration::from_secs(settings.execution_timeout_secs.max(1));

    let mut child = Command::new(&prog_canon);
    augment_command_env(&mut child);
    let mut child = child
        .args(&args)
        .current_dir(&cwd_canon)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn process: {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture stderr".to_string())?;

    let work = async move {
        let read_out = read_limited(stdout, max);
        let read_err = read_limited(stderr, max);
        let wait_child = child.wait();
        let (so_res, se_res, status_res) = tokio::join!(read_out, read_err, wait_child);

        let (stdout_bytes, stdout_trunc) = so_res.map_err(|e| format!("read stdout: {e}"))?;
        let (stderr_bytes, stderr_trunc) = se_res.map_err(|e| format!("read stderr: {e}"))?;
        let status = status_res.map_err(|e| format!("wait: {e}"))?;

        let truncated = stdout_trunc || stderr_trunc;
        Ok::<_, String>((
            lossy_string(stdout_bytes),
            lossy_string(stderr_bytes),
            status.code(),
            truncated,
        ))
    };

    let outcome = timeout(dur, work).await;

    let (timed_out, stdout, stderr, exit_code, truncated) = match outcome {
        Ok(Ok((so, se, code, trunc))) => (false, so, se, code, trunc),
        Ok(Err(e)) => return Err(e),
        Err(_) => (
            true,
            String::new(),
            String::from(
                "Timed out. The process was terminated (tokio drops the child handle on timeout).",
            ),
            None,
            false,
        ),
    };

    let detail = serde_json::json!({
        "program": program,
        "args": args,
        "cwd": cwd,
        "exitCode": exit_code,
        "timedOut": timed_out,
        "truncated": truncated,
    });
    let _ = append_audit(&app, "run_command", detail);

    Ok(CommandResult {
        exit_code,
        stdout,
        stderr,
        truncated,
        timed_out,
    })
}

#[tauri::command]
pub fn read_text_file(app: tauri::AppHandle, path: String) -> Result<String, String> {
    let settings = load_settings(&app)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(&path);
    let canon = resolve_under_roots(p, &settings)?;
    let meta = std::fs::metadata(&canon).map_err(|e| format!("metadata: {e}"))?;
    if !meta.is_file() {
        return Err("not a file".into());
    }
    if meta.len() > settings.max_output_bytes as u64 {
        return Err(format!(
            "file too large ({} bytes); increase max output in settings or choose a smaller file",
            meta.len()
        ));
    }
    let bytes = std::fs::read(&canon).map_err(|e| format!("read: {e}"))?;
    let _ = append_audit(
        &app,
        "read_text_file",
        serde_json::json!({ "path": path, "bytes": bytes.len() }),
    );
    String::from_utf8(bytes).map_err(|e| format!("file is not valid UTF-8: {e}"))
}

#[tauri::command]
pub fn list_directory(app: tauri::AppHandle, path: String) -> Result<Vec<DirEntryInfo>, String> {
    let settings = load_settings(&app)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(&path);
    let canon = resolve_under_roots(p, &settings)?;
    let read = std::fs::read_dir(&canon).map_err(|e| format!("read_dir: {e}"))?;
    let mut out = Vec::new();
    for ent in read {
        let ent = ent.map_err(|e| format!("entry: {e}"))?;
        let meta = ent.metadata().ok();
        let is_dir = meta.map(|m| m.is_dir()).unwrap_or(false);
        out.push(DirEntryInfo {
            name: ent.file_name().to_string_lossy().into_owned(),
            is_dir,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = append_audit(
        &app,
        "list_directory",
        serde_json::json!({ "path": path, "count": out.len() }),
    );
    Ok(out)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInfo {
    pub os: String,
    pub arch: String,
    pub family: String,
    pub home_dir: Option<String>,
    pub temp_dir: Option<String>,
    /// Rust process working directory (often `…/src-tauri` during dev). **Not** the CTI workspace.
    pub cwd: String,
    /// Resolved workspace root from Settings (same tree as the sidebar). Use for paths and run_command cwd.
    pub workspace_root: String,
    pub scripts_dir: String,
    pub workspace_is_custom: bool,
}

#[tauri::command]
pub fn get_environment(app: tauri::AppHandle) -> Result<EnvironmentInfo, String> {
    let settings = load_settings(&app)?;
    let ws = workspace_info_from_settings(&settings)?;
    Ok(EnvironmentInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        family: std::env::consts::FAMILY.to_string(),
        home_dir: dirs::home_dir().map(|p| p.to_string_lossy().into_owned()),
        temp_dir: std::env::temp_dir().to_str().map(|s| s.to_string()),
        cwd: std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        workspace_root: ws.effective_path,
        scripts_dir: ws.scripts_path,
        workspace_is_custom: ws.is_custom_location,
    })
}
