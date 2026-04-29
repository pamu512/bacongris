//! Shell one-liner to `scripts/workflow_runner.py` (bundled in release, dev path in debug).

use std::path::PathBuf;
use std::process::Command;
use tauri::path::BaseDirectory;
use tauri::AppHandle;
use tauri::Manager;

use crate::pty_terminal::terminal_ensure_write;
use crate::settings::resolve_workspace_dir;
use crate::settings::load_settings;

fn pick_python_prefix() -> String {
    #[cfg(windows)]
    {
        if Command::new("py")
            .args(["-3", "-c", "0"])
            .status()
            .ok()
            .is_some_and(|s| s.success())
        {
            return "py -3".to_string();
        }
        if Command::new("python3")
            .arg("--version")
            .status()
            .ok()
            .is_some_and(|s| s.success())
        {
            return "python3".to_string();
        }
        "python".to_string()
    }
    #[cfg(not(windows))]
    {
        if Command::new("python3")
            .arg("--version")
            .status()
            .ok()
            .is_some_and(|s| s.success())
        {
            "python3".to_string()
        } else {
            "python".to_string()
        }
    }
}

#[cfg(windows)]
fn cmd_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', r#"\""#))
}

#[cfg(not(windows))]
fn sh_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || "/._+-:@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Dev checkout: `repo/scripts/workflow_runner.py`. Release: `bundle/resources/...` (see tauri.conf.json).
fn resolve_workflow_runner_script(app: &AppHandle) -> Result<PathBuf, String> {
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/workflow_runner.py");
    if dev.is_file() {
        return Ok(dev);
    }
    app.path()
        .resolve("../scripts/workflow_runner.py", BaseDirectory::Resource)
        .map_err(|e| format!("resolve resource workflow_runner: {e}"))
        .and_then(|p| {
            if p.is_file() {
                Ok(p)
            } else {
                Err("workflow_runner.py is not in the app bundle. Rebuild or reinstall Bacongris.".into())
            }
        })
}

fn normalize_workflow_id(s: &str) -> Result<String, String> {
    let t = s.trim().to_lowercase().replace(['-', ' '], "_");
    match t.as_str() {
        "intelx" => Ok("intelx".into()),
        "cve" | "cve_nvd" | "nvd" => Ok("cve_nvd".into()),
        _ => Err(format!(
            "Unknown workflow \"{s}\". Use: intelx, cve, or cve_nvd."
        )),
    }
}

const MAX_QUERY_CHARS: usize = 2048;

/// IntelX `--query`: single line, bounded length (matches `workflow_runner.py`).
fn sanitize_workflow_query(q: Option<String>) -> Option<String> {
    let full = q?;
    let s = full.lines().next().unwrap_or("").trim();
    if s.is_empty() {
        return None;
    }
    let t: String = s.chars().take(MAX_QUERY_CHARS).collect();
    Some(t)
}

fn sanitize_short_line(q: Option<String>, max: usize) -> Option<String> {
    let full = q?;
    let s = full.lines().next().unwrap_or("").trim();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(max).collect())
}

fn push_intelx_date_arg<F>(line: &mut String, flag: &str, val: &str, quote: F)
where
    F: Fn(&str) -> String,
{
    let t = val.trim();
    if t.is_empty() {
        return;
    }
    line.push_str(flag);
    line.push_str(&quote(t));
}

fn build_terminal_line(
    script: &PathBuf,
    workspace: &PathBuf,
    python: &str,
    workflow: &str,
    query: Option<&str>,
    intelx_start_date: Option<&str>,
    intelx_end_date: Option<&str>,
    intelx_search_limit: Option<&str>,
    cve_start_date: Option<&str>,
    cve_end_date: Option<&str>,
    cve_cvss: Option<&str>,
    cve_cvss_v4: Option<&str>,
) -> Result<String, String> {
    let script = script
        .to_str()
        .ok_or_else(|| "workflow script path: invalid UTF-8".to_string())?;
    let ws = workspace
        .to_str()
        .ok_or_else(|| "workspace path: invalid UTF-8".to_string())?;

    #[cfg(windows)]
    {
        let mut line = format!(
            "{} {} --workspace {} --workflow {}",
            python,
            cmd_quote(script),
            cmd_quote(ws),
            workflow
        );
        if let Some(q) = query {
            if !q.is_empty() {
                line.push_str(" --query ");
                line.push_str(&cmd_quote(q));
            }
        }
        if workflow == "intelx" {
            if let Some(s) = intelx_start_date {
                push_intelx_date_arg(&mut line, " --intelx-start-date ", s, cmd_quote);
            }
            if let Some(s) = intelx_end_date {
                push_intelx_date_arg(&mut line, " --intelx-end-date ", s, cmd_quote);
            }
            if let Some(s) = intelx_search_limit {
                push_intelx_date_arg(&mut line, " --intelx-search-limit ", s, cmd_quote);
            }
        }
        if workflow == "cve_nvd" {
            if let Some(s) = cve_start_date {
                push_intelx_date_arg(&mut line, " --cve-start-date ", s, cmd_quote);
            }
            if let Some(s) = cve_end_date {
                push_intelx_date_arg(&mut line, " --cve-end-date ", s, cmd_quote);
            }
            if let Some(s) = cve_cvss {
                push_intelx_date_arg(&mut line, " --cve-cvss ", s, cmd_quote);
            }
            if let Some(s) = cve_cvss_v4 {
                push_intelx_date_arg(&mut line, " --cve-cvss-v4 ", s, cmd_quote);
            }
        }
        return Ok(format!("{line}\r\n"));
    }
    #[cfg(not(windows))]
    {
        let mut line = format!(
            "{} {} --workspace {} --workflow {}",
            python,
            sh_quote(script),
            sh_quote(ws),
            workflow
        );
        if let Some(q) = query {
            if !q.is_empty() {
                line.push_str(" --query ");
                line.push_str(&sh_quote(q));
            }
        }
        if workflow == "intelx" {
            if let Some(s) = intelx_start_date {
                push_intelx_date_arg(&mut line, " --intelx-start-date ", s, sh_quote);
            }
            if let Some(s) = intelx_end_date {
                push_intelx_date_arg(&mut line, " --intelx-end-date ", s, sh_quote);
            }
            if let Some(s) = intelx_search_limit {
                push_intelx_date_arg(&mut line, " --intelx-search-limit ", s, sh_quote);
            }
        }
        if workflow == "cve_nvd" {
            if let Some(s) = cve_start_date {
                push_intelx_date_arg(&mut line, " --cve-start-date ", s, sh_quote);
            }
            if let Some(s) = cve_end_date {
                push_intelx_date_arg(&mut line, " --cve-end-date ", s, sh_quote);
            }
            if let Some(s) = cve_cvss {
                push_intelx_date_arg(&mut line, " --cve-cvss ", s, sh_quote);
            }
            if let Some(s) = cve_cvss_v4 {
                push_intelx_date_arg(&mut line, " --cve-cvss-v4 ", s, sh_quote);
            }
        }
        Ok(format!("{line}\n"))
    }
}

/// Preflight in Python; sends one line to the integrated terminal from workspace root.
#[tauri::command]
pub fn run_trusted_workflow(
    app: AppHandle,
    workflow: String,
    query: Option<String>,
    intelx_start_date: Option<String>,
    intelx_end_date: Option<String>,
    intelx_search_limit: Option<String>,
    cve_start_date: Option<String>,
    cve_end_date: Option<String>,
    cve_cvss: Option<String>,
    cve_cvss_v4: Option<String>,
) -> Result<serde_json::Value, String> {
    let settings = load_settings(&app)?;
    let workspace = resolve_workspace_dir(&settings)?;
    let script = resolve_workflow_runner_script(&app)?;
    let wid = normalize_workflow_id(&workflow)?;
    let qref = sanitize_workflow_query(query);
    let sref = sanitize_short_line(intelx_start_date, 32);
    let eref = sanitize_short_line(intelx_end_date, 32);
    let lref = sanitize_short_line(intelx_search_limit, 32);
    let cve_sref = sanitize_short_line(cve_start_date, 32);
    let cve_eref = sanitize_short_line(cve_end_date, 32);
    let cve_css_ref = sanitize_short_line(cve_cvss, 64);
    let cve_cv4_ref = sanitize_short_line(cve_cvss_v4, 64);
    let py = pick_python_prefix();
    let line = build_terminal_line(
        &script,
        &workspace,
        &py,
        &wid,
        qref.as_deref(),
        sref.as_deref(),
        eref.as_deref(),
        lref.as_deref(),
        cve_sref.as_deref(),
        cve_eref.as_deref(),
        cve_css_ref.as_deref(),
        cve_cv4_ref.as_deref(),
    )?;

    // Keep a copy before the PTY consume: exact one-liner (no "..." — users have copied that literally).
    let command_sent: String = line.trim_end().to_string();
    let preview = command_sent.clone();
    terminal_ensure_write(app, line, None)?;
    let workspace_display = workspace.to_string_lossy();
    let script_display = script.to_string_lossy();
    let post_run: serde_json::Value = if wid == "intelx" {
        serde_json::json!({
            "outputsRelativeToWorkspace": "Intelx_Crawler/csv_output/<folder>/",
            "typicalFolderPattern": "subfolder name encodes the query email + date range (e.g. *@*_com_2000-01-01_to_2099-12-31)",
            "inChatNextStep": "The run is not finished in chat when this JSON returns—only the shell command was sent. Do not say CSVs already exist. Say: check the bottom terminal; when the run finishes, outputs appear under Intelx_Crawler/csv_output/ (or offer list_directory to verify). If the user wants a summary, then read_text_file on a CSV after list_directory shows files.",
            "ifTerminalShowsChunkedEncoding": "ChunkedEncodingError or IncompleteRead from requests.* inside the container is a transient IntelX / HTTP download issue (network, API, or rate limit). Suggest retry; earlier records may have saved CSVs before the crash."
        })
    } else {
        serde_json::Value::Null
    };
    let other_workflow_message = "Trusted workflow command was sent to the integrated terminal. Watch the bottom panel; preflight and the project run output appear there — not in chat.";
    let message = if wid == "intelx" {
        "Trusted workflow command was sent to the integrated terminal (watch the bottom panel only). This return only confirms the one-liner was sent — the IntelX job may still be running. Piped mode sends four lines (query, start, end, search limit); the JSON intelx* fields are the effective values (defaults match workflow_runner.py when the tool omits them). Do not state that CSVs already exist; say to watch the terminal or use list_directory after the run. See postRun.inChatNextStep."
            .to_string()
    } else {
        other_workflow_message.to_string()
    };
    let body: serde_json::Value = if wid == "intelx" {
        // Match `workflow_runner.py` `_intelx_piped_stdin` — all four lines are sent; `intelx*`
        // in JSON are effective values (defaults when the tool omitted args).
        let eff_start = sref.clone().unwrap_or_else(|| "2000-01-01".to_string());
        let eff_end = eref.clone().unwrap_or_else(|| "2099-12-31".to_string());
        let eff_limit = lref.clone().unwrap_or_else(|| "2000".to_string());
        serde_json::json!({
            "ok": true,
            "message": message,
            "workflow": wid,
            "query": qref,
            "intelxStartDate": eff_start,
            "intelxEndDate": eff_end,
            "intelxSearchLimit": eff_limit,
            "intelxFromToolArgs": {
                "start": sref,
                "end": eref,
                "searchLimit": lref,
            },
            "preview": preview,
            "workspaceRoot": workspace_display,
            "postRun": post_run,
            "workflowRunnerScript": script_display,
            "commandSent": command_sent,
        })
    } else {
        let ceff_s = cve_sref
            .clone()
            .unwrap_or_else(|| "2000-01-01".to_string());
        let ceff_e = cve_eref
            .clone()
            .unwrap_or_else(|| "2099-12-31".to_string());
        serde_json::json!({
            "ok": true,
            "message": message,
            "workflow": wid,
            "query": qref,
            "cveStartDate": ceff_s,
            "cveEndDate": ceff_e,
            "cveFromToolArgs": {
                "start": cve_sref,
                "end": cve_eref,
                "cvss": cve_css_ref,
                "cvssV4": cve_cv4_ref,
            },
            "cveCvss": cve_css_ref.clone().unwrap_or_default(),
            "cveCvssV4": cve_cv4_ref.clone().unwrap_or_default(),
            "preview": preview,
            "workspaceRoot": workspace_display,
            "workflowRunnerScript": script_display,
            "commandSent": command_sent,
        })
    };
    Ok(body)
}
