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

    // Retry logic with exponential backoff
    const MAX_RETRIES: u32 = 3;
    let mut last_error = String::new();
    
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            // Exponential backoff: 1s, 2s, 4s
            let delay = std::time::Duration::from_secs(2u64.pow(attempt - 1));
            tokio::time::sleep(delay).await;
        }

        match try_chat(&client, &url, &body).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = e;
                // Only retry on connection errors, not on HTTP 4xx/5xx
                if !last_error.contains("running") && !last_error.contains("connect") {
                    return Err(last_error);
                }
                continue;
            }
        }
    }
    
    Err(format!("{} (tried {} times)", last_error, MAX_RETRIES))
}

async fn try_chat(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<Value, String> {
    let res = client
        .post(url)
        .json(body)
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
