use crate::active_run::{set_active_pid, ActiveRunState, ClearActiveOnDrop};
use crate::audit::append_audit;
use crate::gui_spawn_env::{clear_stale_docker_host, merged_path};
use crate::paths::{
    is_bare_executable_name, join_workspace_path_for_display, lookup_bare_in_path,
    resolve_path_for_write, resolve_path_for_filesystem_tools, resolve_program_path,
};
use crate::persist_io::write_with_backup;
use crate::session::SessionAllowlist;
use crate::app_data::merged_settings_for_runtime;
use crate::settings::AppSettings;
use crate::workspace::workspace_info_for_app;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tauri::State;
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

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum RiskFlag {
    NetworkActivity,
    CredentialAccess,
    PrivilegeEscalation,
    FileExfiltration,
    SuspiciousPattern,
    DestructiveOperation,
    ExternalDownload,
    CodeExecution,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub flags: Vec<RiskFlag>,
    pub risk_level: RiskLevel,
    pub requires_confirmation: bool,
    pub pattern_signature: String, // For session-based memory
}

#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramDeny {
    pub requested: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied: Option<ProgramDeny>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_assessment: Option<RiskAssessment>,
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

/// If path resolution failed, add context so the model lists dirs instead of guessing shell paths.
fn augment_read_text_file_error(user_path: &str, inner: String, settings: &AppSettings) -> String {
    let p = Path::new(user_path);
    let lower = user_path.to_lowercase();

    if let Ok(target) = join_workspace_path_for_display(p, settings) {
        if let Some(parent) = target.parent() {
            if parent.is_dir() {
                return format!(
                    "{inner}\n\n**Parent directory exists** (file missing or wrong final path): `{}`\nCall **list_directory** on that path, and for IntelX output also list each **subfolder** of `Intelx_Crawler/csv_output/` if needed. Then **read_text_file** using the **exact** `name` from the listing. **Do not** use **send_integrated_terminal** to `ls` or `cat` a **retyped** long filename—shell **stdout is not in chat**; a single character typo in the address (e.g. `gmail` → `gmai`) breaks the path.",
                    parent.display()
                );
            }
        }
    }

    if lower.contains("intelx_crawler")
        && lower.contains("csv")
        && (lower.ends_with(".csv") || lower.contains("csv_output"))
    {
        return format!(
            "{inner}\n\n**IntelX layout:** CSVs are often one level down, e.g. `Intelx_Crawler/csv_output/<run-specific-folder>/...csv`, not only `.../csv_output/<filename>.csv`. **list_directory** `Intelx_Crawler/csv_output`, then subfolders, until the file appears. Copy the filename from the tool; do not guess in the integrated terminal."
        );
    }

    inner
}

/// Risky command patterns that may indicate AI escape attempts
const RISK_PATTERNS: &[(&str, RiskFlag, &str)] = &[
    // Network activity
    (r"(?i)curl\s+.*\|\s*(ba)?sh", RiskFlag::ExternalDownload, "curl piped to shell"),
    (r"(?i)wget\s+.*\|\s*(ba)?sh", RiskFlag::ExternalDownload, "wget piped to shell"),
    (r"(?i)fetch\s+.*\|\s*(ba)?sh", RiskFlag::ExternalDownload, "fetch piped to shell"),
    (r"(?i)nc\s+-[el].*-[el]", RiskFlag::NetworkActivity, "netcat listener (potential backdoor)"),
    (r"(?i)ncat\s+-[el].*-[el]", RiskFlag::NetworkActivity, "ncat listener"),
    (r"(?i)python\s+-m\s+http\.server", RiskFlag::NetworkActivity, "HTTP server"),
    (r"(?i)simplehttpserver", RiskFlag::NetworkActivity, "Python HTTP server"),
    
    // Credential access
    (r"(?i)cat\s+.*\.(env|credentials|aws|ssh|key|pem|p12|pfx)", RiskFlag::CredentialAccess, "credential file access"),
    (r"(?i)cat\s+.*/\.aws/", RiskFlag::CredentialAccess, "AWS credentials"),
    (r"(?i)cat\s+.*/\.ssh/", RiskFlag::CredentialAccess, "SSH keys"),
    (r"(?i)cat\s+.*/\.env", RiskFlag::CredentialAccess, "environment files"),
    
    // Privilege escalation
    (r"(?i)sudo\s+", RiskFlag::PrivilegeEscalation, "sudo command"),
    (r"(?i)su\s+-", RiskFlag::PrivilegeEscalation, "switch user"),
    (r"(?i)pkexec\s+", RiskFlag::PrivilegeEscalation, "pkexec privilege escalation"),
    (r"(?i)doas\s+", RiskFlag::PrivilegeEscalation, "doas privilege escalation"),
    
    // Code execution
    (r"(?i)eval\s*\(", RiskFlag::CodeExecution, "eval()"),
    (r"(?i)exec\s*\(", RiskFlag::CodeExecution, "exec()"),
    (r"(?i)__import__\s*\(\s*os", RiskFlag::CodeExecution, "dynamic import os"),
    (r"(?i)subprocess\.call\s*\(", RiskFlag::CodeExecution, "subprocess call"),
    (r"(?i)os\.system\s*\(", RiskFlag::CodeExecution, "os.system()"),
    (r"(?i)os\.popen\s*\(", RiskFlag::CodeExecution, "os.popen()"),
    
    // Suspicious encodings
    (r"(?i)base64\s+.*\|.*(?:sh|bash|python|ruby|perl)", RiskFlag::SuspiciousPattern, "base64 decode to shell"),
    (r"(?i)(?:xxd|od)\s+.*\|", RiskFlag::SuspiciousPattern, "hex dump piped"),
    
    // Destructive operations
    (r"(?i)rm\s+-rf\s+/", RiskFlag::DestructiveOperation, "recursive root delete"),
    (r"(?i)rm\s+.*--no-preserve-root", RiskFlag::DestructiveOperation, "no preserve root"),
    (r"(?i)dd\s+if=.*of=/dev/(sd|hd|disk|nvme)", RiskFlag::DestructiveOperation, "disk overwrite"),
    (r"(?i)mkfs\.", RiskFlag::DestructiveOperation, "filesystem creation"),
    (r"(?i)>\s*/etc/passwd", RiskFlag::DestructiveOperation, "password file overwrite"),
    (r"(?i)>\s+/etc/shadow", RiskFlag::DestructiveOperation, "shadow file overwrite"),
    
    // File exfiltration (reading sensitive locations)
    (r"(?i)cat\s+/etc/(passwd|shadow|hosts|resolv\.conf)", RiskFlag::FileExfiltration, "system file read"),
    (r"(?i)cat\s+/proc/\d+/environ", RiskFlag::FileExfiltration, "process environment"),
    (r"(?i)cat\s+/proc/\d+/cmdline", RiskFlag::FileExfiltration, "process command line"),
];

/// Analyzes command for risky patterns
fn analyze_risk(program: &str, args: &[String]) -> RiskAssessment {
    let mut flags = Vec::new();
    let mut matched_patterns = Vec::new();
    
    // Combine program and args for analysis
    let command_str = format!("{} {}", program, args.join(" "));
    let lower_cmd = command_str.to_lowercase();
    
    for (pattern, flag, description) in RISK_PATTERNS {
        if let Ok(regex) = regex::Regex::new(pattern) {
            if regex.is_match(&command_str) || regex.is_match(&lower_cmd) {
                if !flags.contains(flag) {
                    flags.push(flag.clone());
                }
                matched_patterns.push(*description);
            }
        }
    }
    
    // Additional heuristic checks
    if program == "python3" || program == "python" || program == "py" {
        // Check for inline Python that looks suspicious
        for arg in args {
            if arg.contains("import os") && arg.contains("system") {
                if !flags.contains(&RiskFlag::CodeExecution) {
                    flags.push(RiskFlag::CodeExecution);
                }
            }
            if arg.contains("import subprocess") {
                if !flags.contains(&RiskFlag::CodeExecution) {
                    flags.push(RiskFlag::CodeExecution);
                }
            }
            if arg.contains("__import__('os')") || arg.contains("__import__(\"os\")") {
                if !flags.contains(&RiskFlag::CodeExecution) {
                    flags.push(RiskFlag::CodeExecution);
                }
            }
        }
    }
    
    // Determine risk level and if confirmation is required
    let (risk_level, requires_confirmation) = if flags.is_empty() {
        (RiskLevel::Low, false)
    } else if flags.contains(&RiskFlag::DestructiveOperation) || 
              flags.contains(&RiskFlag::PrivilegeEscalation) {
        (RiskLevel::Critical, true)
    } else if flags.contains(&RiskFlag::ExternalDownload) || 
              flags.contains(&RiskFlag::CredentialAccess) {
        (RiskLevel::High, true)
    } else if flags.len() >= 2 {
        (RiskLevel::High, true)
    } else {
        (RiskLevel::Medium, true)
    };
    
    // Create a signature for this pattern (for session-based memory)
    let pattern_signature = if matched_patterns.is_empty() {
        format!("{}:{}", program, args.join(" "))
    } else {
        format!("{}:{}", program, matched_patterns.join(","))
    };
    
    RiskAssessment {
        flags,
        risk_level,
        requires_confirmation,
        pattern_signature,
    }
}

/// Map a host file argument to `/workspace/...` in the container if it lies under the work tree.
fn map_arg_for_docker_sandbox(arg: &str, work_dir: &Path) -> Result<String, String> {
    let p = Path::new(arg);
    if !p.is_absolute() {
        return Ok(arg.to_string());
    }
    let c = dunce::canonicalize(p)
        .map_err(|e| format!("{arg} ({e}) — resolve paths before running in Docker"))?;
    if c.starts_with(work_dir) {
        let rel = c
            .strip_prefix(work_dir)
            .map_err(|_| "path under work dir: strip failed".to_string())?;
        let rel = rel
            .to_str()
            .ok_or("path must be UTF-8 in docker sandbox (absolute path to script)")?;
        let rel = rel.replace('\\', "/");
        return Ok(format!("/workspace/{}", rel.trim_start_matches('/')));
    }
    Err(format!(
        "Docker sandbox: absolute paths must be under the work directory ({}). Got: {arg}",
        work_dir.display()
    ))
}

fn build_docker_sandbox_invocation(
    settings: &AppSettings,
    docker_bin: &Path,
    prog_canon: &Path,
    args: &[String],
    host_cwd: &Path,
) -> Result<(PathBuf, Vec<String>), String> {
    let image = settings.docker_sandbox_image.trim();
    let image = if image.is_empty() {
        "python:3.12-slim"
    } else {
        image
    };
    let wd = dunce::canonicalize(host_cwd)
        .map_err(|e| format!("docker: canonicalize work dir: {e}"))?;
    let v_src = wd
        .to_str()
        .ok_or("docker: work path must be UTF-8 to mount into the container")?;
    let exe = prog_canon
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("docker: could not read executable name")?
        .to_string();
    let mut inner: Vec<String> = vec![exe];
    for a in args {
        inner.push(map_arg_for_docker_sandbox(a, &wd)?);
    }
    let mut d = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-i".to_string(),
        "--network=none".to_string(),
    ];
    d.push("-v".to_string());
    d.push(format!("{v_src}:/workspace:rw"));
    d.push("-w".to_string());
    d.push("/workspace".to_string());
    d.push("--memory=512m".to_string());
    d.push(image.to_string());
    d.extend(inner);
    Ok((docker_bin.to_path_buf(), d))
}

#[tauri::command]
pub async fn run_command(
    app: tauri::AppHandle,
    state: State<'_, SessionAllowlist>,
    active_run: State<'_, ActiveRunState>,
    program: String,
    args: Vec<String>,
    cwd: Option<String>,
) -> Result<CommandResult, String> {
    let settings = merged_settings_for_runtime(&app)?;
    let program = program.trim().to_string();
    if program.is_empty() {
        return Err("program is empty".into());
    }
    let program_path = PathBuf::from(&program);
    let log_args = args.clone();
    let session_snapshot: HashSet<String> = state
        .paths
        .lock()
        .map_err(|_| "could not read session allowlist".to_string())?
        .clone();

    let prog_canon = match resolve_program_path(&program_path, &settings, Some(&session_snapshot)) {
        Ok(p) => p,
        Err(e) => {
            let suggested = if is_bare_executable_name(&program) {
                lookup_bare_in_path(&program).map(|p| p.to_string_lossy().into_owned())
            } else {
                None
            };
            return Ok(CommandResult {
                exit_code: None,
                stdout: String::new(),
                stderr: e.clone(),
                truncated: false,
                timed_out: false,
                denied: Some(ProgramDeny {
                    requested: program,
                    reason: e,
                    suggested_path: suggested,
                }),
                risk_assessment: None,
            });
        }
    };

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
            resolve_path_for_filesystem_tools(p, &settings)?
        }
    };

    // Analyze command risk before execution
    let risk_assessment = analyze_risk(&program, &args);
    
    // TODO: In the future, check session-based pattern memory here
    // If pattern was confirmed this session, auto-approve
    // For now, we return the assessment and let frontend handle confirmation

    let max = settings.max_output_bytes.max(1024);
    let dur = Duration::from_secs(settings.execution_timeout_secs.max(1));

    let (spawn_prog, spawn_argv) = if settings.use_docker_sandbox {
        let docker_bin = resolve_program_path(
            std::path::Path::new("docker"),
            &settings,
            Some(&session_snapshot),
        )
        .map_err(|e| {
            format!("Docker sandbox is on in Settings but the docker CLI is not allowlisted/resolved: {e}")
        })?;
        build_docker_sandbox_invocation(
            &settings,
            &docker_bin,
            &prog_canon,
            &args,
            &cwd_canon,
        )?
    } else {
        (prog_canon, args)
    };

    let mut child = Command::new(&spawn_prog);
    augment_command_env(&mut child);
    let mut child = child
        .args(&spawn_argv)
        .current_dir(&cwd_canon)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn process: {e}"))?;

    if let Some(pid) = child.id() {
        set_active_pid(&active_run, pid);
    }
    let _clear_run = ClearActiveOnDrop::new(app.clone());

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
        "args": log_args,
        "dockerSandbox": settings.use_docker_sandbox,
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
        denied: None,
        risk_assessment: Some(risk_assessment),
    })
}

#[tauri::command]
pub fn read_text_file(app: tauri::AppHandle, path: String) -> Result<String, String> {
    let settings = merged_settings_for_runtime(&app)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(&path);
    let canon = match resolve_path_for_filesystem_tools(p, &settings) {
        Ok(c) => c,
        Err(e) => return Err(augment_read_text_file_error(&path, e, &settings)),
    };
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
        serde_json::json!({ "path": path, "resolved": canon.display().to_string(), "bytes": bytes.len() }),
    );
    String::from_utf8(bytes).map_err(|e| format!("file is not valid UTF-8: {e}"))
}

/// Writes a UTF-8 string to a file under allowlisted roots. Replaces the file if it exists; creates
/// parent directories. **Backup:** on overwrite, the previous file is kept as
/// "filename.backup.<timestamp>" next to the file (see persist_io). Max size scales with
/// Settings → max output.
#[tauri::command]
pub fn write_text_file(
    app: tauri::AppHandle,
    path: String,
    content: String,
) -> Result<serde_json::Value, String> {
    let settings = merged_settings_for_runtime(&app)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(&path);
    let max_bytes = settings
        .max_output_bytes
        .saturating_mul(2)
        .max(256 * 1024)
        .min(4 * 1024 * 1024);
    if content.len() > max_bytes {
        return Err(format!(
            "content is {} bytes; max is {} (based on max output in Settings, capped at 4 MiB).",
            content.len(),
            max_bytes
        ));
    }
    let target = resolve_path_for_write(p, &settings)?;
    if target.is_dir() {
        return Err("refusing to write: path is a directory".into());
    }
    write_with_backup(&target, &content)?;
    let _ = append_audit(
        &app,
        "write_text_file",
        serde_json::json!({
            "path": path,
            "target": target.to_string_lossy(),
            "bytes": content.len()
        }),
    );
    Ok(serde_json::json!({
        "ok": true,
        "path": target.to_string_lossy(),
        "bytesWritten": content.len(),
    }))
}

#[tauri::command]
pub fn list_directory(app: tauri::AppHandle, path: String) -> Result<Vec<DirEntryInfo>, String> {
    let settings = merged_settings_for_runtime(&app)?;
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(&path);
    let canon = resolve_path_for_filesystem_tools(p, &settings)?;
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
    /// `python3 --version` stdout/stderr when on PATH; `None` if not found.
    pub python3_version: Option<String>,
    /// `python --version` when on PATH and distinct from the python3 probe; `None` if not found.
    pub python_version: Option<String>,
}

fn probe_python_version(exe: &str) -> Option<String> {
    let output = std::process::Command::new(exe)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let out = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let line = if !out.is_empty() { out } else { err };
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

#[tauri::command]
pub fn get_environment(app: tauri::AppHandle) -> Result<EnvironmentInfo, String> {
    let ws = workspace_info_for_app(&app)?;
    let python3_version = probe_python_version("python3");
    let python_version = probe_python_version("python");
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
        python3_version,
        python_version,
    })
}
