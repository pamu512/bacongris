import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { runAgenticTurn } from "./lib/agent/loop";
import { CTI_SYSTEM_PROMPT } from "./lib/agent/systemPrompt";
import type { AppSettings, OllamaMessage } from "./lib/agent/types";
import type { WorkspaceInfo } from "./lib/workspace";
import { IntegratedTerminal } from "./IntegratedTerminal";
import "./App.css";

const defaultSettings = (): AppSettings => ({
  workspacePath: "",
  ollamaBaseUrl: "http://127.0.0.1:11434",
  model: "llama3.1",
  allowlistedRoots: [],
  allowedExecutables: [],
  executionTimeoutSecs: 120,
  maxOutputBytes: 512 * 1024,
});

function normalizeSettings(raw: Partial<AppSettings>): AppSettings {
  const d = defaultSettings();
  return {
    ...d,
    ...raw,
    workspacePath: raw.workspacePath ?? d.workspacePath,
    ollamaBaseUrl: raw.ollamaBaseUrl ?? d.ollamaBaseUrl,
    model: raw.model ?? d.model,
    allowlistedRoots: raw.allowlistedRoots ?? d.allowlistedRoots,
    allowedExecutables: raw.allowedExecutables ?? d.allowedExecutables,
    executionTimeoutSecs: raw.executionTimeoutSecs ?? d.executionTimeoutSecs,
    maxOutputBytes: raw.maxOutputBytes ?? d.maxOutputBytes,
  };
}

function rootsToText(roots: string[]) {
  return roots.join("\n");
}

function textToLines(s: string) {
  return s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

function withStableIds(msgs: OllamaMessage[]): OllamaMessage[] {
  return msgs.map((m) =>
    m.localId ? m : { ...m, localId: crypto.randomUUID() },
  );
}

export default function App() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [rootsText, setRootsText] = useState("");
  const [execText, setExecText] = useState("");
  const [messages, setMessages] = useState<OllamaMessage[]>([]);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editDraft, setEditDraft] = useState("");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [audit, setAudit] = useState<unknown[]>([]);
  const [workspace, setWorkspace] = useState<WorkspaceInfo | null>(null);
  const [scriptEntries, setScriptEntries] = useState<
    { name: string; isDir: boolean }[]
  >([]);
  const [workspaceRunAnalysis, setWorkspaceRunAnalysis] = useState<string | null>(
    null,
  );
  const [terminalOpen, setTerminalOpen] = useState(true);
  const endRef = useRef<HTMLDivElement | null>(null);

  const loadAudit = useCallback(async () => {
    try {
      const rows = await invoke<unknown[]>("get_recent_audit", { limit: 50 });
      setAudit(rows);
    } catch {
      setAudit([]);
    }
  }, []);

  const refreshWorkspace = useCallback(async () => {
    try {
      const info = await invoke<WorkspaceInfo>("get_workspace_info");
      setWorkspace(info);
      try {
        const entries = await invoke<{ name: string; isDir: boolean }[]>(
          "list_directory",
          { path: info.scriptsPath },
        );
        setScriptEntries(entries);
      } catch {
        setScriptEntries([]);
      }
    } catch {
      setWorkspace(null);
      setScriptEntries([]);
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const s = await invoke<AppSettings>("load_settings_cmd");
        const n = normalizeSettings(s);
        setSettings(n);
        setRootsText(rootsToText(n.allowlistedRoots));
        setExecText(rootsToText(n.allowedExecutables));
        await refreshWorkspace();
      } catch {
        setStatus("Could not load settings (backend unavailable in browser preview).");
      }
    })();
  }, [refreshWorkspace]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  const systemMessage = useMemo<OllamaMessage>(() => {
    const wsHint = workspace
      ? `\n\n## Active workspace (use for all paths and run_command cwd)\n- workspaceRoot: ${workspace.effectivePath}\n- scriptsDir: ${workspace.scriptsPath}\n`
      : "";
    return { role: "system", content: CTI_SYSTEM_PROMPT + wsHint };
  }, [workspace]);

  const cancelMessageEdit = useCallback(() => {
    setEditingIndex(null);
    setEditDraft("");
  }, []);

  const beginMessageEdit = useCallback(
    (index: number) => {
      const m = messages[index];
      if (m?.role !== "user" || busy) return;
      setEditingIndex(index);
      setEditDraft(m.content ?? "");
    },
    [messages, busy],
  );

  const saveMessageEdit = useCallback(async () => {
    const idx = editingIndex;
    if (idx === null || busy) return;
    const text = editDraft.trim();
    if (!text) return;

    const prefix = messages.slice(0, idx);
    const userMsg: OllamaMessage = {
      role: "user",
      content: text,
      localId: crypto.randomUUID(),
    };

    setMessages([...prefix, userMsg]);
    cancelMessageEdit();
    setBusy(true);
    setStatus(null);

    const withoutSystem = prefix.filter((m) => m.role !== "system");
    const transcript: OllamaMessage[] = [systemMessage, ...withoutSystem, userMsg];

    const { transcript: full, error } = await runAgenticTurn(transcript);
    const forUi = withStableIds(full.filter((m) => m.role !== "system"));
    setMessages(forUi);
    if (error) setStatus(error);
    setBusy(false);
    await loadAudit();
    await refreshWorkspace();
  }, [
    editingIndex,
    editDraft,
    busy,
    messages,
    systemMessage,
    cancelMessageEdit,
    loadAudit,
    refreshWorkspace,
  ]);

  const persistSettings = async (next: AppSettings) => {
    await invoke("save_settings_cmd", { settings: next });
    setSettings(next);
  };

  const onSaveSettings = async () => {
    const next: AppSettings = {
      ...settings,
      allowlistedRoots: textToLines(rootsText),
      allowedExecutables: textToLines(execText),
    };
    try {
      await persistSettings(next);
      setStatus("Settings saved.");
      await loadAudit();
      await refreshWorkspace();
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  };

  const pickWorkspaceFolder = async () => {
    try {
      const choice = await open({
        directory: true,
        multiple: false,
        title: "Choose workspace folder",
      });
      const path =
        typeof choice === "string"
          ? choice
          : Array.isArray(choice) && choice[0]
            ? choice[0]
            : null;
      if (path) {
        setSettings((s) => ({ ...s, workspacePath: path }));
        setStatus("Workspace path updated — click Save settings to apply.");
      }
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  };

  const onSend = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setBusy(true);
    setStatus(null);

    const userMsg: OllamaMessage = {
      role: "user",
      content: text,
      localId: crypto.randomUUID(),
    };
    const withoutSystem = messages.filter((m) => m.role !== "system");
    const transcript: OllamaMessage[] = [
      systemMessage,
      ...withoutSystem,
      userMsg,
    ];
    setMessages([...withoutSystem, userMsg]);

    const { transcript: full, error } = await runAgenticTurn(transcript);
    const forUi = withStableIds(full.filter((m) => m.role !== "system"));
    setMessages(forUi);
    if (error) setStatus(error);
    setBusy(false);
    await loadAudit();
    await refreshWorkspace();
  };

  const onClearChat = () => {
    cancelMessageEdit();
    setMessages([]);
    setStatus(null);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-title">Bacongris CTI Agent</span>
          <span className="brand-sub">Local · Ollama · Scripts</span>
        </div>
        <div className="top-actions">
          <button
            type="button"
            className="btn ghost"
            onClick={() => {
              setSettingsOpen(true);
              void loadAudit();
              void refreshWorkspace();
            }}
          >
            Settings
          </button>
          <button type="button" className="btn ghost" onClick={onClearChat}>
            Clear chat
          </button>
          <button
            type="button"
            className={`btn ghost${terminalOpen ? " active-toggle" : ""}`}
            onClick={() => setTerminalOpen((v) => !v)}
            title="Show or hide the integrated terminal"
          >
            Terminal
          </button>
        </div>
      </header>

      <div className="body">
        <aside className="workspace-panel" aria-label="Workspace">
          <h2 className="workspace-title">Workspace</h2>
          <p className="workspace-path" title={workspace?.effectivePath ?? ""}>
            {workspace
              ? workspace.effectivePath
              : "…"}
          </p>
            <p className="workspace-hint">
            Scripts live in <code>scripts/</code> inside this folder (allowlisted for tools). On
            first open, a <code>venv_run.sh</code> helper is created there: from the workspace root
            run <code>./scripts/venv_run.sh YourProjectFolder</code> to create a per-project venv,
            install <code>requirements.txt</code>, and run <code>main.py</code> in one step.
          </p>
          <div className="workspace-actions">
            <button
              type="button"
              className="btn small"
              onClick={async () => {
                try {
                  await invoke("prepare_workspace_layout");
                  await refreshWorkspace();
                  setStatus("Workspace folders ready.");
                } catch (e) {
                  setStatus(e instanceof Error ? e.message : String(e));
                }
              }}
            >
              Prepare folders
            </button>
            <button
              type="button"
              className="btn small ghost"
              onClick={async () => {
                try {
                  await invoke("open_workspace_in_os");
                } catch (e) {
                  setStatus(e instanceof Error ? e.message : String(e));
                }
              }}
            >
              Open in file manager
            </button>
            <button
              type="button"
              className="btn small ghost"
              onClick={async () => {
                try {
                  const report = await invoke<unknown>(
                    "analyze_workspace_run_requirements",
                    {
                      full_workspace: true,
                      use_cache: true,
                    },
                  );
                  setWorkspaceRunAnalysis(JSON.stringify(report, null, 2));
                  setStatus("Workspace run requirements updated (see panel below).");
                  await loadAudit();
                } catch (e) {
                  setStatus(e instanceof Error ? e.message : String(e));
                }
              }}
            >
              Scan run requirements
            </button>
          </div>
          {workspaceRunAnalysis && (
            <div className="workspace-analysis">
              <div className="workspace-files-head">Run requirements (scan)</div>
              <pre className="workspace-analysis-pre">{workspaceRunAnalysis}</pre>
            </div>
          )}
          <div className="workspace-files">
            <div className="workspace-files-head">scripts/</div>
            <ul className="workspace-list">
              {scriptEntries.length === 0 && (
                <li className="muted">Empty — add scripts here.</li>
              )}
              {scriptEntries.map((e) => (
                <li key={e.name}>
                  {e.isDir ? "📁 " : "📄 "}
                  {e.name}
                </li>
              ))}
            </ul>
          </div>
        </aside>

        <div className="content-column">
        <main className="main">
        <section className="chat">
          {messages.length === 0 && (
            <div className="empty">
              <p>
                Ask a question or describe a CTI task. Use{" "}
                <strong>Prepare folders</strong> in the workspace panel, then add
                scripts under <code>scripts/</code>. Extra directories can still
                be allowlisted in Settings.
              </p>
              <p className="hint">
                Requires Ollama running locally with a tool-capable model (e.g.
                llama3.1).
              </p>
              <p className="hint">
                Sent <strong>user</strong> messages can be edited from the{" "}
                <strong>Edit</strong> link — the thread below that point is
                discarded and the agent runs again (like Cursor).
              </p>
            </div>
          )}
          <ul className="messages">
            {messages.map((m, i) => (
              <li
                key={m.localId ?? `msg-${i}`}
                className={`msg msg-${m.role}`}
              >
                {m.role === "user" ? (
                  <div className="msg-user-head">
                    <div className="msg-role">user</div>
                    {editingIndex !== i && !busy && (
                      <button
                        type="button"
                        className="btn link"
                        onClick={() => beginMessageEdit(i)}
                      >
                        Edit
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="msg-role">{m.role}</div>
                )}
                {m.role === "user" && editingIndex === i ? (
                  <div className="msg-edit">
                    <textarea
                      className="msg-edit-input"
                      rows={4}
                      value={editDraft}
                      onChange={(e) => setEditDraft(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Escape") {
                          e.preventDefault();
                          cancelMessageEdit();
                        }
                        if (e.key === "Enter" && !e.shiftKey) {
                          e.preventDefault();
                          void saveMessageEdit();
                        }
                      }}
                      aria-label="Edit message"
                    />
                    <div className="msg-edit-actions">
                      <button
                        type="button"
                        className="btn small primary"
                        onClick={() => void saveMessageEdit()}
                      >
                        Save &amp; resend
                      </button>
                      <button
                        type="button"
                        className="btn small ghost"
                        onClick={cancelMessageEdit}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {m.content != null && m.content !== "" && (
                      <pre className="msg-body">{m.content}</pre>
                    )}
                    {m.tool_calls && m.tool_calls.length > 0 && (
                      <pre className="msg-tools">
                        {JSON.stringify(m.tool_calls, null, 2)}
                      </pre>
                    )}
                  </>
                )}
              </li>
            ))}
            {busy && (
              <li className="msg msg-assistant pending">
                <div className="msg-role">assistant</div>
                <div className="msg-body">Working…</div>
              </li>
            )}
            <div ref={endRef} />
          </ul>
        </section>

        <footer className="composer">
          {status && <div className="status">{status}</div>}
          <div className="composer-row">
            <textarea
              className="input"
              rows={3}
              placeholder="Message the agent…"
              value={input}
              disabled={busy}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void onSend();
                }
              }}
            />
            <button
              type="button"
              className="btn primary"
              disabled={busy}
              onClick={() => void onSend()}
            >
              Send
            </button>
          </div>
        </footer>
      </main>
        <IntegratedTerminal
          visible={terminalOpen}
          cwd={workspace?.effectivePath ?? null}
        />
        </div>
      </div>

      {settingsOpen && (
        <div
          className="drawer-backdrop"
          role="presentation"
          onClick={() => setSettingsOpen(false)}
        >
          <aside
            className="drawer"
            role="dialog"
            aria-label="Settings"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="drawer-head">
              <h2>Settings</h2>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setSettingsOpen(false)}
              >
                Close
              </button>
            </div>

            <section className="settings-section">
              <h3>Workspace</h3>
              <p className="field-help">
                The workspace is always allowlisted. Leave empty to use the app
                default (<code>…/BacongrisCTIAgent/workspace</code>).
              </p>
              <label className="field">
                <span>Custom workspace path (optional)</span>
                <input
                  value={settings.workspacePath}
                  placeholder="Default app workspace if empty"
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      workspacePath: e.target.value,
                    }))
                  }
                />
              </label>
              <div className="drawer-actions inline">
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => void pickWorkspaceFolder()}
                >
                  Choose folder…
                </button>
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() =>
                    setSettings((s) => ({ ...s, workspacePath: "" }))
                  }
                >
                  Use app default location
                </button>
              </div>
              {workspace && (
                <p className="field-help mono">
                  Resolved: {workspace.effectivePath}
                  {workspace.isCustomLocation ? " (custom)" : " (default)"}
                </p>
              )}
            </section>

            <label className="field">
              <span>Ollama base URL</span>
              <input
                value={settings.ollamaBaseUrl}
                onChange={(e) =>
                  setSettings((s) => ({ ...s, ollamaBaseUrl: e.target.value }))
                }
              />
            </label>

            <label className="field">
              <span>Model</span>
              <input
                value={settings.model}
                onChange={(e) =>
                  setSettings((s) => ({ ...s, model: e.target.value }))
                }
              />
            </label>

            <label className="field">
              <span>Allowlisted directories (one per line)</span>
              <textarea
                rows={5}
                value={rootsText}
                onChange={(e) => setRootsText(e.target.value)}
              />
            </label>

            <label className="field">
              <span>
                Allowed executables (full paths, one per line; e.g. /usr/bin/python3)
              </span>
              <textarea
                rows={4}
                value={execText}
                onChange={(e) => setExecText(e.target.value)}
              />
            </label>

            <div className="field-row">
              <label className="field">
                <span>Timeout (seconds)</span>
                <input
                  type="number"
                  min={1}
                  value={settings.executionTimeoutSecs}
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      executionTimeoutSecs: Number(e.target.value) || 1,
                    }))
                  }
                />
              </label>
              <label className="field">
                <span>Max output (bytes)</span>
                <input
                  type="number"
                  min={1024}
                  step={1024}
                  value={settings.maxOutputBytes}
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      maxOutputBytes: Number(e.target.value) || 1024,
                    }))
                  }
                />
              </label>
            </div>

            <div className="drawer-actions">
              <button
                type="button"
                className="btn primary"
                onClick={() => void onSaveSettings()}
              >
                Save settings
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={async () => {
                  try {
                    await invoke("clear_audit_log");
                    await loadAudit();
                    setStatus("Audit log cleared.");
                  } catch (e) {
                    setStatus(e instanceof Error ? e.message : String(e));
                  }
                }}
              >
                Clear audit log
              </button>
            </div>

            <div className="audit">
              <h3>Recent tool audit</h3>
              <ul>
                {audit.length === 0 && <li className="muted">No entries yet.</li>}
                {audit.map((row, i) => (
                  <li key={i}>
                    <pre>{JSON.stringify(row, null, 2)}</pre>
                  </li>
                ))}
              </ul>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
