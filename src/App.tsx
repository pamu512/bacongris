import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { runAgenticTurn } from "./lib/agent/loop";
import {
  runTaskVerifier,
  type TaskVerifierResult,
} from "./lib/agent/verifier";
import { buildCtiSystemMessageContent } from "./lib/agent/systemPrompt";
import type { AppSettings, ChatAttachment, OllamaMessage } from "./lib/agent/types";
import {
  filesToChatAttachments,
  mergeUserMessageForModel,
  systemHintForUserTurn,
} from "./lib/chatAttachments";
import type { WorkspaceInfo } from "./lib/workspace";
import { IntegratedTerminal } from "./IntegratedTerminal";
import {
  summarizeAgentTurn,
  toolCallsToSummaryLines,
  toolResultForDisplay,
  workspaceIndexProjectNames,
  workspaceIndexStatus,
} from "./lib/chatDisplay";
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

function isAnalyzeWorkspaceTool(m: OllamaMessage): boolean {
  return (
    m.tool_name === "analyze_workspace_run_requirements" ||
    m.name === "analyze_workspace_run_requirements"
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
  const [pendingAttachments, setPendingAttachments] = useState<ChatAttachment[]>(
    [],
  );
  const [attachmentReadBusy, setAttachmentReadBusy] = useState(false);
  const [composerActiveDrop, setComposerActiveDrop] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
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
  /** Fast index JSON from the first user message of the chat; shown in Thinking + injected into system. */
  const [sessionIndexJson, setSessionIndexJson] = useState<string | null>(null);
  const [sessionIndexedForPath, setSessionIndexedForPath] = useState<string | null>(
    null,
  );
  const [sessionIndexLoading, setSessionIndexLoading] = useState(false);
  const [thinkingOpen, setThinkingOpen] = useState(false);
  const [lastTurnThought, setLastTurnThought] = useState<ReturnType<
    typeof summarizeAgentTurn
  > | null>(null);
  const [lastTurnVerification, setLastTurnVerification] =
    useState<TaskVerifierResult | null>(null);
  const [turnPanelKey, setTurnPanelKey] = useState(0);
  /** Full terminal output vs slim bar; the dock is always in the layout. */
  const [terminalExpanded, setTerminalExpanded] = useState(true);
  const endRef = useRef<HTMLDivElement | null>(null);
  const lastWorkspacePathRef = useRef<string | undefined>(undefined);

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

  useEffect(() => {
    const current = workspace?.effectivePath;
    if (
      lastWorkspacePathRef.current !== undefined &&
      current !== lastWorkspacePathRef.current
    ) {
      setSessionIndexJson(null);
      setSessionIndexedForPath(null);
    }
    lastWorkspacePathRef.current = current;
  }, [workspace?.effectivePath]);

  const prepareSessionIndexForTurn = useCallback(
    async (isFirstUserMessage: boolean): Promise<string | null> => {
      if (!workspace) return null;
      if (!isFirstUserMessage) {
        return sessionIndexJson;
      }
      if (
        sessionIndexJson &&
        sessionIndexedForPath === workspace.effectivePath
      ) {
        return sessionIndexJson;
      }
      const report = await invoke<unknown>("analyze_workspace_run_requirements", {
        use_cache: true,
      });
      const json = JSON.stringify(report, null, 2);
      setSessionIndexJson(json);
      setSessionIndexedForPath(workspace.effectivePath);
      return json;
    },
    [workspace, sessionIndexJson, sessionIndexedForPath],
  );

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
    const prev = messages[idx];
    if (!prev || prev.role !== "user") return;
    const keptAtt = prev.attachments;
    if (!text && !keptAtt?.length) return;

    const prefix = messages.slice(0, idx);
    const userMsg: OllamaMessage = {
      role: "user",
      content: text,
      ...(keptAtt?.length ? { attachments: keptAtt } : {}),
      localId: crypto.randomUUID(),
    };

    setMessages([...prefix, userMsg]);
    cancelMessageEdit();
    setBusy(true);
    setStatus(null);
    setLastTurnThought(null);
    setLastTurnVerification(null);
    const runStarted = performance.now();

    const withoutSystem = prefix.filter((m) => m.role !== "system");
    const isFirstUserMessage =
      withoutSystem.filter((m) => m.role === "user").length === 0;
    if (isFirstUserMessage && workspace) {
      const needFetch =
        !sessionIndexJson || sessionIndexedForPath !== workspace.effectivePath;
      if (needFetch) setSessionIndexLoading(true);
    }
    let indexJson: string | null = null;
    try {
      indexJson = await prepareSessionIndexForTurn(isFirstUserMessage);
    } finally {
      setSessionIndexLoading(false);
    }
    const systemMsg: OllamaMessage = {
      role: "system",
      content: buildCtiSystemMessageContent(workspace, indexJson, {
        lastUserMessage: systemHintForUserTurn(
          text,
          keptAtt?.length ? keptAtt : undefined,
        ),
      }),
    };
    const transcript: OllamaMessage[] = [systemMsg, ...withoutSystem, userMsg];

    const { transcript: full, error } = await runAgenticTurn(transcript);
    const forUi = withStableIds(full.filter((m) => m.role !== "system"));
    setMessages(forUi);
    const newSlice = forUi.slice(withoutSystem.length + 1);
    const thought = summarizeAgentTurn(newSlice, performance.now() - runStarted, {
      loadedWorkspaceIndex: isFirstUserMessage && Boolean(indexJson),
    });
    setLastTurnThought(thought);
    setTurnPanelKey((k) => k + 1);
    if (error) {
      setStatus(error);
      setLastTurnVerification(null);
    } else {
      setStatus("Task check…");
      try {
        setLastTurnVerification(
          await runTaskVerifier(
            mergeUserMessageForModel(
              text,
              keptAtt?.length ? keptAtt : undefined,
            ),
            newSlice,
          ),
        );
        setStatus(null);
      } catch (e) {
        setLastTurnVerification(null);
        setStatus(e instanceof Error ? e.message : String(e));
      }
    }
    setBusy(false);
    await loadAudit();
    await refreshWorkspace();
  }, [
    editingIndex,
    editDraft,
    busy,
    messages,
    workspace,
    sessionIndexJson,
    sessionIndexedForPath,
    prepareSessionIndexForTurn,
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

  /**
   * @param autoSave If true, persist settings immediately (e.g. from the Workspace sidebar).
   *  If false, only update the draft — user must click "Save settings" (Settings drawer).
   */
  const addFilesFromList = useCallback(async (list: FileList | null) => {
    if (list == null || list.length === 0) return;
    setAttachmentReadBusy(true);
    try {
      const next = await filesToChatAttachments(list);
      setPendingAttachments((prev) => [...prev, ...next]);
    } finally {
      setAttachmentReadBusy(false);
    }
  }, []);

  const removePendingAttachment = useCallback((id: string) => {
    setPendingAttachments((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const pickWorkspaceFolder = async (autoSave = false) => {
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
        const next: AppSettings = {
          ...settings,
          workspacePath: path,
          allowlistedRoots: textToLines(rootsText),
          allowedExecutables: textToLines(execText),
        };
        if (autoSave) {
          await persistSettings(next);
          setStatus("Workspace folder saved.");
          await loadAudit();
          await refreshWorkspace();
        } else {
          setSettings(next);
          setStatus("Workspace path updated — click Save settings to apply.");
        }
      }
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  };

  const onSend = async () => {
    const text = input.trim();
    const atch = pendingAttachments;
    if ((!text && !atch.length) || busy || attachmentReadBusy) return;
    setInput("");
    setPendingAttachments([]);
    setBusy(true);
    setStatus(null);
    setLastTurnThought(null);
    setLastTurnVerification(null);
    const runStarted = performance.now();

    const userMsg: OllamaMessage = {
      role: "user",
      content: text,
      ...(atch.length ? { attachments: atch } : {}),
      localId: crypto.randomUUID(),
    };
    const withoutSystem = messages.filter((m) => m.role !== "system");
    setMessages([...withoutSystem, userMsg]);

    const isFirstUserMessage =
      withoutSystem.filter((m) => m.role === "user").length === 0;
    if (isFirstUserMessage && workspace) {
      const needFetch =
        !sessionIndexJson || sessionIndexedForPath !== workspace.effectivePath;
      if (needFetch) setSessionIndexLoading(true);
    }
    let indexJson: string | null = null;
    try {
      indexJson = await prepareSessionIndexForTurn(isFirstUserMessage);
    } finally {
      setSessionIndexLoading(false);
    }
    const systemMsg: OllamaMessage = {
      role: "system",
      content: buildCtiSystemMessageContent(workspace, indexJson, {
        lastUserMessage: systemHintForUserTurn(text, atch.length ? atch : undefined),
      }),
    };
    const transcript: OllamaMessage[] = [systemMsg, ...withoutSystem, userMsg];

    const { transcript: full, error } = await runAgenticTurn(transcript);
    const forUi = withStableIds(full.filter((m) => m.role !== "system"));
    setMessages(forUi);
    const newSlice = forUi.slice(withoutSystem.length + 1);
    const thought = summarizeAgentTurn(newSlice, performance.now() - runStarted, {
      loadedWorkspaceIndex: isFirstUserMessage && Boolean(indexJson),
    });
    setLastTurnThought(thought);
    setTurnPanelKey((k) => k + 1);
    if (error) {
      setStatus(error);
      setLastTurnVerification(null);
    } else {
      setStatus("Task check…");
      try {
        setLastTurnVerification(
          await runTaskVerifier(
            mergeUserMessageForModel(text, atch.length ? atch : undefined),
            newSlice,
          ),
        );
        setStatus(null);
      } catch (e) {
        setLastTurnVerification(null);
        setStatus(e instanceof Error ? e.message : String(e));
      }
    }
    setBusy(false);
    await loadAudit();
    await refreshWorkspace();
  };

  const onClearChat = () => {
    cancelMessageEdit();
    setPendingAttachments([]);
    setMessages([]);
    setStatus(null);
    setSessionIndexJson(null);
    setSessionIndexedForPath(null);
    setSessionIndexLoading(false);
    setLastTurnThought(null);
    setLastTurnVerification(null);
  };

  const thinkingStatusText = workspaceIndexStatus(
    sessionIndexJson,
    sessionIndexLoading,
  );
  const indexProjectNames = workspaceIndexProjectNames(sessionIndexJson);

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
            className={`btn ghost${terminalExpanded ? " active-toggle" : ""}`}
            onClick={() => setTerminalExpanded((v) => !v)}
            title={
              terminalExpanded
                ? "Collapse terminal output (bar stays visible)"
                : "Expand terminal output"
            }
          >
            {terminalExpanded ? "Collapse terminal" : "Expand terminal"}
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
          <div className="workspace-path-row">
            <button
              type="button"
              className="btn small primary"
              onClick={() => void pickWorkspaceFolder(true)}
            >
              Change workspace folder…
            </button>
            <button
              type="button"
              className="btn small ghost"
              onClick={() => {
                setSettingsOpen(true);
              }}
            >
              Open Settings
            </button>
          </div>
          <p className="workspace-hint minimal">
            The path above is not editable as text here — use{" "}
            <strong>Change workspace folder</strong> (saves immediately) or{" "}
            <strong>Settings</strong> → type or <em>Choose folder</em> → <em>Save settings</em>.
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
        <div className="main-chat-stack">
        <main className="main">
        {(lastTurnThought || lastTurnVerification) && (
          <section
            key={turnPanelKey}
            className="turn-meta"
            aria-label="Last model run and task check"
          >
            {lastTurnThought && (
              <div className="turn-thought">
                <div className="turn-thought-kicker">
                  Thought for {lastTurnThought.durationLabel}s
                </div>
                <p className="turn-thought-lead">{lastTurnThought.headline}</p>
                <details className="turn-thought-details">
                  <summary className="turn-thought-summary">
                    {lastTurnThought.subline}
                  </summary>
                  {lastTurnThought.detailLines.length > 0 && (
                    <ul className="turn-thought-bullets">
                      {lastTurnThought.detailLines.map((line, i) => (
                        <li key={i}>{line}</li>
                      ))}
                    </ul>
                  )}
                </details>
              </div>
            )}
            {lastTurnVerification && (
              <div
                className={`task-verifier task-verifier--${lastTurnVerification.verdict}`}
                aria-label="Task verifier"
              >
                <div className="task-verifier-kicker">Second-opinion task check</div>
                <p className="task-verifier-verdict">
                  <span className="task-verifier-badge">{lastTurnVerification.verdict}</span>
                  <span className="task-verifier-conf">
                    confidence {(lastTurnVerification.confidence * 100).toFixed(0)}%
                  </span>
                </p>
                <p className="task-verifier-summary">{lastTurnVerification.summary}</p>
                {lastTurnVerification.gaps.length > 0 && (
                  <ul className="task-verifier-gaps">
                    {lastTurnVerification.gaps.map((g, i) => (
                      <li key={i}>{g}</li>
                    ))}
                  </ul>
                )}
                {lastTurnVerification.parseWarning && (
                  <p className="task-verifier-warn">Verifier parse: {lastTurnVerification.parseWarning}</p>
                )}
              </div>
            )}
          </section>
        )}
        <section
          className="thinking-panel"
          aria-label="Session workspace index for inspection"
        >
          <button
            type="button"
            className="thinking-toggle"
            onClick={() => setThinkingOpen((o) => !o)}
            aria-expanded={thinkingOpen}
          >
            <span className="thinking-toggle-label">Workspace index</span>
            <span className="thinking-toggle-sub">{thinkingStatusText}</span>
          </button>
          {thinkingOpen && (
            <div className="thinking-body">
              {sessionIndexLoading && !sessionIndexJson && (
                <p className="thinking-placeholder">Building workspace index…</p>
              )}
              {sessionIndexJson && (
                <>
                  {indexProjectNames.length > 0 && (
                    <ul className="thinking-project-list">
                      {indexProjectNames.map((name) => (
                        <li key={name}>
                          <code>{name}</code>
                        </li>
                      ))}
                    </ul>
                  )}
                  <details className="thinking-full-json">
                    <summary>Full index JSON (for the model)</summary>
                    <pre className="thinking-pre">{sessionIndexJson}</pre>
                  </details>
                </>
              )}
              {!sessionIndexLoading && !sessionIndexJson && (
                <p className="thinking-placeholder muted">
                  The first message in this chat runs a fast project index and injects it for the
                  model. Clear chat to reset.
                </p>
              )}
            </div>
          )}
        </section>
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
                Use <strong>Attach files</strong> or drag files onto the composer
                to send text/CSV/JSON with your message (UTF-8; size limits apply).
              </p>
              <p className="hint">
                Sent <strong>user</strong> messages can be edited from the{" "}
                <strong>Edit</strong> link — the thread below that point is
                discarded and the agent runs again.
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
                    {m.attachments && m.attachments.length > 0 && (
                      <p className="msg-edit-attach-note">
                        This turn includes <strong>{m.attachments.length}</strong> attached
                        file(s); only the text below is edited — same files are re-sent.
                      </p>
                    )}
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
                    {m.role === "tool" &&
                    isAnalyzeWorkspaceTool(m) &&
                    sessionIndexJson &&
                    (m.content?.length ?? 0) > 4000 ? (
                      <>
                        <p className="msg-tool-note">
                          Large <code>analyze_workspace_run_requirements</code> output — see{" "}
                          <strong>Workspace index</strong> above.
                        </p>
                        <details className="msg-tool-details">
                          <summary>Raw tool output</summary>
                          <pre className="msg-body">{m.content}</pre>
                        </details>
                      </>
                    ) : m.role === "tool" ? (
                      <div className="msg-tool-compact">
                        <div className="msg-tool-meta">
                          {m.tool_name ?? m.name ?? "tool"}
                        </div>
                        {(() => {
                          const r = toolResultForDisplay(m.content);
                          return (
                            <>
                              <p
                                className={
                                  r.isError ? "msg-tool-err" : "msg-tool-ok"
                                }
                              >
                                {r.headline}
                              </p>
                              <details className="msg-tool-details">
                                <summary>Full output</summary>
                                <pre className="msg-body msg-body-raw">
                                  {r.raw}
                                </pre>
                              </details>
                            </>
                          );
                        })()}
                      </div>
                    ) : m.role === "user" ? (
                      <>
                        {m.content != null && m.content.trim() !== "" && (
                          <pre className="msg-body">{m.content}</pre>
                        )}
                        {m.attachments && m.attachments.length > 0 && (
                          <ul
                            className="msg-attach-list"
                            aria-label="Files attached to this message"
                          >
                            {m.attachments.map((a) => (
                              <li key={a.id} className="msg-attach-chip">
                                <span className="msg-attach-name">{a.name}</span>
                                <span className="msg-attach-meta">
                                  {a.omittedReason
                                    ? a.omittedReason === "too_large"
                                      ? " — not inlined (too large)"
                                      : a.omittedReason === "binary"
                                        ? " — not inlined (binary)"
                                        : " — empty"
                                    : ` — ${(a.sizeBytes / 1024).toFixed(
                                        a.sizeBytes < 10_240 ? 1 : 0,
                                      )} KB in model context`}
                                </span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </>
                    ) : (
                      <>
                        {m.content != null && m.content.trim() !== "" && (
                          <pre className="msg-body">{m.content}</pre>
                        )}
                        {m.tool_calls && m.tool_calls.length > 0 && (
                          <div className="msg-tool-calls">
                            <div className="msg-tool-calls-h">Tool calls</div>
                            <ul className="msg-tool-calls-ul">
                              {toolCallsToSummaryLines(m.tool_calls).map(
                                (t, j) => (
                                  <li key={j}>
                                    <code className="msg-tool-call-line">
                                      {t.line}
                                    </code>
                                  </li>
                                ),
                              )}
                            </ul>
                            <details className="msg-raw-tool-json">
                              <summary>Raw JSON</summary>
                              <pre className="msg-tools">
                                {JSON.stringify(m.tool_calls, null, 2)}
                              </pre>
                            </details>
                          </div>
                        )}
                        {m.role === "assistant" && m.thinking && m.thinking.trim() !== "" && (
                          <details className="msg-model-reasoning">
                            <summary>Model chain-of-thought (optional)</summary>
                            <pre className="msg-body msg-body-cot">{m.thinking}</pre>
                          </details>
                        )}
                      </>
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

        <footer
          className={`composer${composerActiveDrop ? " composer--drop" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!busy) setComposerActiveDrop(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            if (e.currentTarget === e.target) setComposerActiveDrop(false);
          }}
          onDrop={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setComposerActiveDrop(false);
            if (busy || attachmentReadBusy) return;
            const fl = e.dataTransfer?.files;
            if (fl?.length) void addFilesFromList(fl);
          }}
        >
          {status && <div className="status">{status}</div>}
          {pendingAttachments.length > 0 && (
            <ul className="composer-attach-pending" aria-label="Files to send with next message">
              {pendingAttachments.map((a) => (
                <li key={a.id} className="composer-attach-chip">
                  <span className="msg-attach-name">{a.name}</span>
                  {a.omittedReason ? (
                    <span className="msg-attach-warn"> ({a.omittedReason})</span>
                  ) : null}
                  <button
                    type="button"
                    className="btn link composer-attach-remove"
                    onClick={() => removePendingAttachment(a.id)}
                    aria-label={`Remove ${a.name}`}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="composer-row">
            <textarea
              className="input"
              rows={3}
              placeholder="Message the agent… (you can attach files below)"
              value={input}
              disabled={busy || attachmentReadBusy}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void onSend();
                }
              }}
            />
            <div className="composer-actions">
              <input
                ref={fileInputRef}
                type="file"
                className="visually-hidden"
                multiple
                aria-hidden
                tabIndex={-1}
                onChange={(e) => {
                  void addFilesFromList(e.target.files);
                  e.target.value = "";
                }}
              />
              <button
                type="button"
                className="btn ghost"
                disabled={busy || attachmentReadBusy}
                title="Attach text / log / CSV (UTF-8). Large or binary files are listed but not inlined."
                onClick={() => fileInputRef.current?.click()}
              >
                {attachmentReadBusy ? "Reading…" : "Attach files"}
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={busy || attachmentReadBusy}
                onClick={() => void onSend()}
              >
                Send
              </button>
            </div>
          </div>
          <p className="composer-hint" role="note">
            <strong>Attach</strong> adds files to the next message (text, CSV, JSON, logs; max ~256
            KB per file, UTF-8; drag-and-drop here). Bigger or binary files appear as a note for the
            model — use the workspace and <code>read_text_file</code> when needed. For IntelX / CVE
            the agent may use <code>run_trusted_workflow</code>. The model does not read the
            terminal stream—paste output if it should see it.
          </p>
        </footer>
      </main>
        </div>
        <div
          className={`terminal-split${terminalExpanded ? "" : " terminal-split--collapsed"}`}
          aria-label="Terminal column"
        >
        <IntegratedTerminal
          visible
          expanded={terminalExpanded}
          onToggleExpand={() => setTerminalExpanded((e) => !e)}
          cwd={workspace?.effectivePath ?? null}
        />
        </div>
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
