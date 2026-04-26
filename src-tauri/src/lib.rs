mod audit;
mod executor;
mod gui_spawn_env;
mod ollama;
mod paths;
mod pty_terminal;
mod settings;
mod workspace;
mod workspace_analyze;

use audit::{clear_audit_log, get_recent_audit};
use executor::{get_environment, list_directory, read_text_file, run_command};
use ollama::ollama_chat;
use settings::{load_settings, save_settings, settings_path, AppSettings};
use workspace::{get_workspace_info, open_workspace_in_os, prepare_workspace_layout};
use workspace_analyze::analyze_workspace_run_requirements;
use pty_terminal::{
    terminal_ensure_write, terminal_is_active, terminal_kill, terminal_resize, terminal_spawn,
    terminal_write, TerminalState,
};

#[tauri::command]
fn load_settings_cmd(app: tauri::AppHandle) -> Result<AppSettings, String> {
    load_settings(&app)
}

#[tauri::command]
fn save_settings_cmd(app: tauri::AppHandle, settings: AppSettings) -> Result<(), String> {
    save_settings(&app, &settings)
}

#[tauri::command]
fn settings_file_path(app: tauri::AppHandle) -> Result<String, String> {
    settings_path(&app).map(|p| p.to_string_lossy().into_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(TerminalState::default())
        .invoke_handler(tauri::generate_handler![
            load_settings_cmd,
            save_settings_cmd,
            settings_file_path,
            ollama_chat,
            run_command,
            read_text_file,
            list_directory,
            get_environment,
            get_recent_audit,
            clear_audit_log,
            get_workspace_info,
            prepare_workspace_layout,
            open_workspace_in_os,
            analyze_workspace_run_requirements,
            terminal_spawn,
            terminal_write,
            terminal_ensure_write,
            terminal_is_active,
            terminal_resize,
            terminal_kill,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_roundtrip() {
        let s = AppSettings::default();
        let j = serde_json::to_string(&s).unwrap();
        let _: AppSettings = serde_json::from_str(&j).unwrap();
    }
}
