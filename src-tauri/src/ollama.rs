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
    chat_with_settings_ex(settings, messages, tools, false).await
}

/// `json_response`: set Ollama `format: "json"` so the model must emit valid JSON (used by task verifier).
async fn chat_with_settings_ex(
    settings: &AppSettings,
    messages: Value,
    tools: Option<Value>,
    json_response: bool,
) -> Result<Value, String> {
    let base = settings.ollama_base_url.trim_end_matches('/');
    let url = format!("{base}/api/chat");

    let mut body = serde_json::json!({
        "model": settings.model,
        "messages": messages,
        "stream": false,
    });
    if json_response {
        body["format"] = serde_json::json!("json");
    }
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
        let mut err = format!("Ollama HTTP {}: {}", status, txt);
        if status.as_u16() == 500 && txt.contains("parsing tool call") {
            err.push_str(
                " (Tip: some models emit invalid tool JSON; update Ollama, try another model, or use Clear chat if a bad turn is stuck in history.)",
            );
        }
        return Err(err);
    }

    let v: Value = res
        .json()
        .await
        .map_err(|e| format!("invalid JSON from Ollama: {e}"))?;

    ollama_debug_log_response(&v);

    Ok(v)
}

/// Text-only chat (no tool definitions) with `format: "json"` for structured verifier output.
#[tauri::command]
pub async fn ollama_verifier_chat(
    app: tauri::AppHandle,
    messages: Value,
) -> Result<Value, String> {
    let settings = load_settings(&app)?;
    chat_with_settings_ex(&settings, messages, None, true).await
}

/// Dev-side trace (see stderr when running `cargo tauri dev` / app from a terminal). No full bodies.
fn ollama_debug_log_response(v: &Value) {
    let model = v.get("model").and_then(|m| m.as_str()).unwrap_or("?");
    let done = v.get("done").and_then(|d| d.as_bool());
    let top_keys: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    eprintln!("[bacongris:ollama] model={model} done={done:?} top_level_keys={top_keys:?}");
    if let Some(msg) = v.get("message").and_then(|m| m.as_object()) {
        let keys: Vec<String> = msg.keys().cloned().collect();
        let content_len = msg
            .get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.len());
        let thinking_len = msg
            .get("thinking")
            .and_then(|c| c.as_str())
            .map(|s| s.len());
        let tc = msg
            .get("tool_calls")
            .and_then(|t| t.as_array())
            .map(|a| a.len());
        eprintln!(
            "[bacongris:ollama] message keys={keys:?} content_len={content_len:?} thinking_len={thinking_len:?} tool_calls={tc:?}"
        );
    } else {
        eprintln!("[bacongris:ollama] missing or non-object `message`");
    }
}
