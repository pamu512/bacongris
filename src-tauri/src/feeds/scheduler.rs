//! Background: poll enabled feeds when `poll_interval_minutes` elapses.
use rusqlite::params;
use tauri::Manager;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::api::HttpApiState;
use crate::app_data::AppStore;

use super::run_poll_feed_work;

fn due_feed_ids(now: i64, g: &rusqlite::Connection) -> Result<Vec<String>, String> {
    let mut s = g
        .prepare(
            r#"
        SELECT id FROM feeds
        WHERE enabled = 1
          AND COALESCE(poll_interval_minutes, 0) > 0
          AND (
            last_poll_time IS NULL
            OR (?1 - last_poll_time) >= (poll_interval_minutes * 60)
          )
        "#,
        )
        .map_err(|e| e.to_string())?;
    let rows = s
        .query_map(params![now], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut v = vec![];
    for row in rows {
        v.push(row.map_err(|e| e.to_string())?);
    }
    Ok(v)
}

/// Runs every 60s; for each **due** feed, runs the same path as the `poll_feed` command.
async fn tick(app: tauri::AppHandle) {
    let now = chrono::Utc::now().timestamp();
    let ids: Result<Vec<String>, String> = {
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string());
        g.and_then(|db| due_feed_ids(now, &*db))
    };
    let ids = match ids {
        Ok(x) => x,
        Err(e) => {
            eprintln!("feed scheduler: {e}");
            return;
        }
    };
    if ids.is_empty() {
        return;
    }
    let http = app.state::<HttpApiState>();
    for id in ids {
        if let Err(e) = run_poll_feed_work(&app, &*http, &id).await {
            eprintln!("feed scheduler poll {id}: {e}");
        }
    }
}

pub fn spawn_feed_poll_scheduler(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut t = interval(Duration::from_secs(60));
        t.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            tick(app.clone()).await;
        }
    });
}
