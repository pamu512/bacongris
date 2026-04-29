mod active_run;
mod app_data;
mod audit;
mod campaigns_util;
mod executor;
mod ioc;
mod api;
mod enrichment;
mod feeds;
mod correlation;
mod threat_time;
mod gui_spawn_env;
mod ollama;
mod paths;
mod persist_io;
mod pty_terminal;
mod session;
mod settings;
mod workflow_runner;
mod workspace;
mod workspace_analyze;

use tauri::Manager;

use active_run::cancel_active_run;
use active_run::ActiveRunState;
use app_data::AppStore;
use app_data::{
    check_active_workspace_path, create_agent, create_workspace_profile, get_app_state,
    get_llm_context_extras, import_local_storage_conversation, list_agents, list_workspace_profiles,
    load_conversation, save_conversation, set_active_agent_id, set_active_profile_id,
};
use audit::{clear_audit_log, get_recent_audit};
use executor::{get_environment, list_directory, read_text_file, run_command, write_text_file};
use ollama::{ollama_chat, ollama_verifier_chat};
use settings::{load_settings, save_settings, settings_path, AppSettings};
use session::{session_allow_for_program, SessionAllowlist};
use workflow_runner::run_trusted_workflow;
use workspace::{
    get_workspace_info, ingest_files_from_data, ingest_uploads, open_workspace_in_os,
    prepare_workspace_layout,
};
use workspace_analyze::analyze_workspace_run_requirements;
use api::{api_request, HttpApiState};
use correlation::{
    add_ioc_relationship, campaign_analysis, find_path, ioc_pivot, suggest_pivots,
};
use enrichment::{
    enrich_abusech, enrich_ioc, enrich_otx, enrich_shodan, enrich_virustotal,
};
use feeds::{
    add_feed, feed_health, feed_search, feed_stats, get_feed_status, list_feeds, poll_feed,
    source_reputation,
};
use ioc::{
    ioc_create, ioc_delete, ioc_export_stix, ioc_import_misp, ioc_import_stix, ioc_maintenance,
    ioc_search, ioc_update, run_ioc_maintenance_on_conn,
};
use threat_time::{
    campaign_compare, campaign_track, emerging_threats, ioc_timeline, record_sighting,
};
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
        .setup(|app| {
            let store = AppStore::initialize(&app.handle())
                .map_err(|e| format!("Bacongris app data: {e}"))?;
            {
                let g = store
                    .db
                    .lock()
                    .map_err(|e| format!("Bacongris app data: {e}"))?;
                run_ioc_maintenance_on_conn(&*g)
                    .map_err(|e| format!("ioc maintenance: {e}"))?;
            }
            app.manage(store);
            feeds::scheduler::spawn_feed_poll_scheduler(app.handle().clone());
            Ok(())
        })
        .manage(TerminalState::default())
        .manage(SessionAllowlist::default())
        .manage(ActiveRunState::default())
        .manage(HttpApiState::default())
        .invoke_handler(tauri::generate_handler![
            load_settings_cmd,
            save_settings_cmd,
            settings_file_path,
            ollama_chat,
            ollama_verifier_chat,
            run_command,
            cancel_active_run,
            session_allow_for_program,
            read_text_file,
            write_text_file,
            list_directory,
            get_environment,
            get_recent_audit,
            clear_audit_log,
            get_workspace_info,
            ingest_uploads,
            ingest_files_from_data,
            prepare_workspace_layout,
            open_workspace_in_os,
            analyze_workspace_run_requirements,
            run_trusted_workflow,
            list_workspace_profiles,
            get_app_state,
            set_active_profile_id,
            create_workspace_profile,
            list_agents,
            set_active_agent_id,
            create_agent,
            load_conversation,
            save_conversation,
            import_local_storage_conversation,
            check_active_workspace_path,
            get_llm_context_extras,
            terminal_spawn,
            terminal_write,
            terminal_ensure_write,
            terminal_is_active,
            terminal_resize,
            terminal_kill,
            ioc_create,
            ioc_search,
            ioc_update,
            ioc_delete,
            ioc_import_stix,
            ioc_import_misp,
            ioc_export_stix,
            ioc_maintenance,
            api_request,
            enrich_ioc,
            enrich_virustotal,
            enrich_shodan,
            enrich_abusech,
            enrich_otx,
            add_feed,
            list_feeds,
            get_feed_status,
            poll_feed,
            feed_search,
            feed_stats,
            feed_health,
            source_reputation,
            add_ioc_relationship,
            ioc_pivot,
            find_path,
            suggest_pivots,
            campaign_analysis,
            record_sighting,
            ioc_timeline,
            campaign_track,
            emerging_threats,
            campaign_compare,
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
