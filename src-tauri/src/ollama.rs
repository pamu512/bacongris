use crate::settings::{load_settings, AppSettings};
use serde_json::Value;

#[tauri::command]
pub async fn ollama_chat(
    app: tauri::AppHandle,
    messages: Value,
    tools: Option<Value>,
) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    chat_with_settings(&settings, messages, tools).await
}

pub async fn chat_with_settings(
    settings: &AppSettings,
    messages: Value,
    tools: Option<Value>,
) -> Result<Value, String> {
    let base = settings.ollama_base_url.trim_end_matches('/');
    let url = format!("{base}/api/chat");

    let mut body = serde_json::json!({
        "model": settings.model,
        "messages": messages,
        "stream": false,
    });
    if let Some(t) = tools {
        body["tools"] = t;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let res = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Ollama request failed (is Ollama running?): {e}"))?;

    if !res.status().is_success() {
        let status = res.status();
        let txt = res.text().await.unwrap_or_default();
        return Err(format!("Ollama HTTP {}: {}", status, txt));
    }

    res.json()
        .await
        .map_err(|e| format!("invalid JSON from Ollama: {e}"))
}
