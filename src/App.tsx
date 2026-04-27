import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { runAgenticTurn } from "./lib/agent/loop";
import { CTI_SYSTEM_PROMPT } from "./lib/agent/systemPrompt";
import type {
  ApiRateLimitConfig,
  AppSettings,
  OllamaMessage,
} from "./lib/agent/types";
import type {
  AgentInfo,
  AppStateV2,
  WorkspaceInfo,
  WorkspaceProfile,
} from "./lib/workspace";
import { IntegratedTerminal } from "./IntegratedTerminal";
import {
  findRunCommandDenial,
  type RunCommandDenied,
} from "./lib/runCommandDenial";
import "./App.css";

type PendingUpload = { path: string; name: string; size: number };

/** Matches backend `ioc_search` / IocRow (camelCase). */
type IocActivityRow = {
  id: string;
  value: string;
  iocType: string;
  lastSeen: number;
  mitreTechniques: string[];
  isFalsePositive: boolean;
  source?: string | null;
};

/** Filled into the chat composer for a one-click “latest IOCs” triage (agent uses ioc_search). */
const LATEST_IOC_TRIAGE_PROMPT =
  "Use the ioc_search tool with limit 25 (active profile + global, same scope as the sidebar). Give a short triage: group by ioc type and source, call out the highest-priority values, and suggest next steps (e.g. enrich_*) only for a few key items if useful.";

type FeedHealthRow = {
  feedId: string;
  name: string;
  ftype: string;
  enabled: number;
  pollIntervalMinutes: number | null;
  lastPollTime: number | null;
  lastError: string | null;
  lastFailureTime: number | null;
  consecutiveFailures: number;
  stalenessSeconds: number | null;
  isStale: boolean;
  isUnhealthy: boolean;
};

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  const chunk = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    for (let j = i; j < Math.min(i + chunk, bytes.length); j++) {
      binary += String.fromCharCode(bytes[j]!);
    }
  }
  return btoa(binary);
}

const defaultSettings = (): AppSettings => ({
  workspacePath: "",
  ollamaBaseUrl: "http://127.0.0.1:11434",
  model: "llama3.1",
  allowlistedRoots: [],
  allowedExecutables: [],
  executionTimeoutSecs: 120,
  maxOutputBytes: 512 * 1024,
  useDockerSandbox: false,
  dockerSandboxImage: "python:3.12-slim",
  apiKeys: {},
  apiRateLimits: {},
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
    useDockerSandbox: raw.useDockerSandbox ?? d.useDockerSandbox,
    dockerSandboxImage: raw.dockerSandboxImage?.trim() || d.dockerSandboxImage,
    apiKeys: raw.apiKeys ?? d.apiKeys ?? {},
    apiRateLimits: raw.apiRateLimits ?? d.apiRateLimits ?? {},
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

function parseApiKeysJson(text: string): Record<string, string> | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text.trim() || "{}");
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return null;
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== "string") return null;
    out[k] = v;
  }
  return out;
}

function parseApiRateLimitsJson(
  text: string,
): Record<string, ApiRateLimitConfig> | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text.trim() || "{}");
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return null;
  }
  const out: Record<string, ApiRateLimitConfig> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
    const o = v as Record<string, unknown>;
    const rpm = Number(o.requestsPerMinute);
    const rpd = Number(o.requestsPerDay);
    const ttlRaw = o.cacheTtlSecs;
    const ttl =
      ttlRaw === undefined || ttlRaw === null
        ? undefined
        : Number(ttlRaw);
    if (!Number.isFinite(rpm) || rpm < 0) return null;
    if (!Number.isFinite(rpd) || rpd < 0) return null;
    if (ttl !== undefined && (!Number.isFinite(ttl) || ttl < 0)) return null;
    out[k] = {
      requestsPerMinute: Math.floor(rpm),
      requestsPerDay: Math.floor(rpd),
      ...(ttl !== undefined ? { cacheTtlSecs: Math.floor(ttl) } : {}),
    };
  }
  return out;
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
  const [apiKeysText, setApiKeysText] = useState("{}");
  const [apiRateLimitsText, setApiRateLimitsText] = useState("{}");
  const prevSettingsOpen = useRef(false);
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
  const [iocActivity, setIocActivity] = useState<IocActivityRow[] | null>(null);
  const [iocActivityErr, setIocActivityErr] = useState<string | null>(null);
  const [feedHealth, setFeedHealth] = useState<FeedHealthRow[] | null>(null);
  const [feedHealthErr, setFeedHealthErr] = useState<string | null>(null);
  const [workspaceRunAnalysis, setWorkspaceRunAnalysis] = useState<string | null>(
    null,
  );
  const [terminalOpen, setTerminalOpen] = useState(true);
  const [workspaceProfiles, setWorkspaceProfiles] = useState<WorkspaceProfile[]>([]);
  const [appStateV2, setAppStateV2] = useState<AppStateV2 | null>(null);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  type LlmContextExtras = {
    userRules: string;
    memoryExcerpt: string;
    /** First 8kiB of PREFERENCES.md in workspace, when present. */
    preferencesExcerpt: string;
  };
  const [promptExtras, setPromptExtras] = useState<LlmContextExtras | null>(null);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [newAgentOpen, setNewAgentOpen] = useState(false);
  const [newAgentTitleDraft, setNewAgentTitleDraft] = useState("Chat");
  /** File paths in workspace uploads/; shown until Send, then embedded in the user message. */
  const [pendingUploads, setPendingUploads] = useState<PendingUpload[]>([]);
  const endRef = useRef<HTMLDivElement | null>(null);
  const runAbortRef = useRef<AbortController | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const composerInputRef = useRef<HTMLTextAreaElement | null>(null);

  const runCommandDenial = useMemo(
    () => findRunCommandDenial(messages),
    [messages],
  );

  const onCancelRun = useCallback(() => {
    runAbortRef.current?.abort();
    void invoke("cancel_active_run");
  }, []);

  const onFileInputChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      e.target.value = "";
      if (!files?.length) return;
      if (!workspace?.pathAccessible) {
        setStatus("Need an accessible workspace to save uploads.");
        return;
      }
      setStatus(null);
      const items: { fileName: string; dataBase64: string }[] = [];
      for (let i = 0; i < files.length; i++) {
        const f = files[i]!;
        if (f.size < 1) continue;
        const buf = await f.arrayBuffer();
        items.push({ fileName: f.name, dataBase64: arrayBufferToBase64(buf) });
      }
      if (items.length === 0) return;
      try {
        const list = await invoke<PendingUpload[]>("ingest_files_from_data", { items });
        setPendingUploads((p) => [...p, ...list]);
      } catch (er) {
        setStatus(er instanceof Error ? er.message : String(er));
      }
    },
    [workspace?.pathAccessible],
  );

  const onAttachFiles = useCallback(async () => {
    if (busy) return;
    if (!workspace?.pathAccessible) {
      setStatus("Need an accessible workspace to save uploads (Settings or profile).");
      return;
    }
    setStatus(null);
    let paths: string[] = [];
    try {
      const choice = await open({
        multiple: true,
        directory: false,
        title: "Add files to analyze",
      });
      paths =
        choice == null ? [] : Array.isArray(choice) ? choice : [choice];
    } catch {
      fileInputRef.current?.click();
      return;
    }
    if (paths.length === 0) return;
    try {
      const list = await invoke<PendingUpload[]>("ingest_uploads", { sourcePaths: paths });
      setPendingUploads((p) => [...p, ...list]);
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  }, [busy, workspace?.pathAccessible]);

  const loadAudit = useCallback(async () => {
    try {
      const rows = await invoke<unknown[]>("get_recent_audit", { limit: 50 });
      setAudit(rows);
    } catch {
      setAudit([]);
    }
  }, []);

  const loadProfilesAgentsAndContext = useCallback(async () => {
    try {
      const [p, a, st, ex] = await Promise.all([
        invoke<WorkspaceProfile[]>("list_workspace_profiles").catch(() => []),
        invoke<AgentInfo[]>("list_agents").catch(() => []),
        invoke<AppStateV2>("get_app_state").catch(() => null),
        invoke<{
          userRules: string;
          memoryExcerpt: string;
          preferencesExcerpt?: string;
        }>("get_llm_context_extras").catch(() => null),
      ]);
      setWorkspaceProfiles(p);
      setAgents(a);
      if (st) setAppStateV2(st);
      if (ex) {
        setPromptExtras({
          userRules: ex.userRules,
          memoryExcerpt: ex.memoryExcerpt,
          preferencesExcerpt: ex.preferencesExcerpt ?? "",
        });
      }
    } catch {
      // ignore
    }
  }, []);

  const loadConversationFromDisk = useCallback(async () => {
    try {
      const raw = await invoke<unknown[]>("load_conversation");
      if (Array.isArray(raw) && raw.length > 0) {
        setMessages(withStableIds(raw as OllamaMessage[]));
      } else {
        setMessages([]);
      }
    } catch {
      // tauri or empty
    }
  }, []);

  const refreshWorkspace = useCallback(async () => {
    try {
      const info = await invoke<WorkspaceInfo>("get_workspace_info");
      setWorkspace(info);
      try {
        if (info.pathAccessible) {
          const entries = await invoke<{ name: string; isDir: boolean }[]>(
            "list_directory",
            { path: info.scriptsPath },
          );
          setScriptEntries(entries);
        } else {
          setScriptEntries([]);
        }
      } catch {
        setScriptEntries([]);
      }
    } catch {
      setWorkspace(null);
      setScriptEntries([]);
    }
  }, []);

  const loadIocActivity = useCallback(async () => {
    try {
      const rows = await invoke<IocActivityRow[]>("ioc_search", {
        limit: 25,
        include_false_positives: false,
      });
      setIocActivity(rows);
      setIocActivityErr(null);
    } catch (e) {
      setIocActivity(null);
      setIocActivityErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadFeedHealth = useCallback(async () => {
    try {
      const r = await invoke<{
        feeds: FeedHealthRow[];
        asOf: number;
      }>("feed_health");
      setFeedHealth(r.feeds ?? []);
      setFeedHealthErr(null);
    } catch (e) {
      setFeedHealth(null);
      setFeedHealthErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  /** One control refreshes both Recent IOCs and feed health (same data the agent uses via tools). */
  const refreshSidePanelCti = useCallback(async () => {
    await Promise.all([loadIocActivity(), loadFeedHealth()]);
  }, [loadIocActivity, loadFeedHealth]);

  const insertLatestIocTriagePrompt = useCallback(() => {
    if (busy) return;
    setInput((prev) => {
      const t = LATEST_IOC_TRIAGE_PROMPT;
      const p = prev.trim();
      if (!p) return t;
      return `${p}\n\n${t}`;
    });
    requestAnimationFrame(() => {
      const el = composerInputRef.current;
      el?.focus();
      el?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  }, [busy]);

  const bootstrapApp = useCallback(async () => {
    try {
      const s = await invoke<AppSettings>("load_settings_cmd");
      const n = normalizeSettings(s);
      setSettings(n);
      setRootsText(rootsToText(n.allowlistedRoots));
      setExecText(rootsToText(n.allowedExecutables));
      setApiKeysText(JSON.stringify(n.apiKeys ?? {}, null, 2));
      setApiRateLimitsText(JSON.stringify(n.apiRateLimits ?? {}, null, 2));
      await refreshWorkspace();
      await loadProfilesAgentsAndContext();
      await loadConversationFromDisk();
    } catch {
      setStatus("Could not load settings (backend unavailable in browser preview).");
    }
  }, [
    loadConversationFromDisk,
    loadProfilesAgentsAndContext,
    refreshWorkspace,
  ]);

  useEffect(() => {
    void bootstrapApp();
  }, [bootstrapApp]);

  useEffect(() => {
    if (settingsOpen && !prevSettingsOpen.current) {
      setApiKeysText(JSON.stringify(settings.apiKeys ?? {}, null, 2));
      setApiRateLimitsText(JSON.stringify(settings.apiRateLimits ?? {}, null, 2));
    }
    prevSettingsOpen.current = settingsOpen;
  }, [settingsOpen, settings]);

  useEffect(() => {
    if (!workspace?.pathAccessible) {
      setIocActivity(null);
      setIocActivityErr(null);
      setFeedHealth(null);
      setFeedHealthErr(null);
      return;
    }
    void refreshSidePanelCti();
  }, [
    workspace?.pathAccessible,
    workspace?.effectivePath,
    appStateV2?.activeProfileId,
    refreshSidePanelCti,
  ]);

  useEffect(() => {
    try {
      if (sessionStorage.getItem("bacongris_v2_import_dismissed")) return;
      const raw = localStorage.getItem("bacongris_autosave");
      if (raw) {
        const p = JSON.parse(raw) as { messages?: OllamaMessage[] };
        if (p?.messages && p.messages.length > 0) {
          setImportModalOpen(true);
        }
      }
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  // Auto-save messages to on-disk JSONL (Issue 4). Debounced to avoid I/O on every keypress.
  useEffect(() => {
    if (messages.length === 0) return;
    const t = window.setTimeout(() => {
      void (async () => {
        try {
          await invoke("save_conversation", { messages });
        } catch {
          // browser preview: no tauri
        }
      })();
    }, 500);
    return () => window.clearTimeout(t);
  }, [messages]);

  const systemMessage = useMemo<OllamaMessage>(() => {
    const wsHint = workspace
      ? `\n\n## Active workspace (use for all paths and run_command cwd)\n- workspaceRoot: ${workspace.effectivePath}\n- scriptsDir: ${workspace.scriptsPath}\n${!workspace.pathAccessible && workspace.pathError ? `- **Path issue:** ${workspace.pathError}\n` : ""}`
      : "";
    let extra = "";
    if (promptExtras) {
      if (promptExtras.userRules.trim()) {
        extra += `\n\n## User rules (L1; USER_RULES.md or profile — respect these)\n${promptExtras.userRules}\n`;
      }
      if (promptExtras.memoryExcerpt.trim()) {
        extra += `\n\n## Long-term notes (NOTES.md excerpt — L2)\n${promptExtras.memoryExcerpt}\n`;
      }
      if (promptExtras.preferencesExcerpt.trim()) {
        extra += `\n\n## Long-term preferences (PREFERENCES.md excerpt)\n${promptExtras.preferencesExcerpt}\n`;
      }
    }
    return { role: "system", content: CTI_SYSTEM_PROMPT + wsHint + extra };
  }, [workspace, promptExtras]);

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
    const ac = new AbortController();
    runAbortRef.current = ac;
    setBusy(true);
    setStatus(null);

    const withoutSystem = prefix.filter((m) => m.role !== "system");
    const transcript: OllamaMessage[] = [systemMessage, ...withoutSystem, userMsg];

    try {
      const { transcript: full, error } = await runAgenticTurn(transcript, {
        signal: ac.signal,
      });
      const forUi = withStableIds(full.filter((m) => m.role !== "system"));
      setMessages(forUi);
      if (error) setStatus(error);
    } finally {
      if (runAbortRef.current === ac) runAbortRef.current = null;
      setBusy(false);
      await loadAudit();
      await refreshWorkspace();
    }
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
    const keys = parseApiKeysJson(apiKeysText);
    if (keys === null) {
      setStatus(
        "apiKeys: invalid JSON. Use an object of string values, e.g. {\"virustotal\":\"…\"}.",
      );
      return;
    }
    const limits = parseApiRateLimitsJson(apiRateLimitsText);
    if (limits === null) {
      setStatus(
        "apiRateLimits: invalid JSON. Use an object of { requestsPerMinute, requestsPerDay, cacheTtlSecs? } per key.",
      );
      return;
    }
    const next: AppSettings = {
      ...settings,
      allowlistedRoots: textToLines(rootsText),
      allowedExecutables: textToLines(execText),
      apiKeys: keys,
      apiRateLimits: limits,
    };
    try {
      await persistSettings(next);
      setStatus("Settings saved.");
      await loadAudit();
      await refreshWorkspace();
      await loadProfilesAgentsAndContext();
      try {
        const ex = await invoke<{
          userRules: string;
          memoryExcerpt: string;
          preferencesExcerpt?: string;
        }>("get_llm_context_extras");
        setPromptExtras({
          userRules: ex.userRules,
          memoryExcerpt: ex.memoryExcerpt,
          preferencesExcerpt: ex.preferencesExcerpt ?? "",
        });
      } catch {
        /* ignore */
      }
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
    if (busy) return;
    if (!text && !pendingUploads.length) return;

    const attachmentBlock = pendingUploads.length
      ? (() => {
          const list = pendingUploads
            .map(
              (u) =>
                `- ${u.path}  (${u.name} — ${u.size.toLocaleString()} bytes)`,
            )
            .join("\n");
          return `---
**Attached files (use the read_text_file tool with these absolute paths. UTF-8 text only; max file size = Settings → max output bytes):**
${list}`;
        })()
      : "";

    const userContent = text
      ? attachmentBlock
        ? `${text}\n\n${attachmentBlock}`
        : text
      : attachmentBlock;

    setInput("");
    setPendingUploads([]);
    const ac = new AbortController();
    runAbortRef.current = ac;
    setBusy(true);
    setStatus(null);

    const userMsg: OllamaMessage = {
      role: "user",
      content: userContent,
      localId: crypto.randomUUID(),
    };
    const withoutSystem = messages.filter((m) => m.role !== "system");
    const transcript: OllamaMessage[] = [
      systemMessage,
      ...withoutSystem,
      userMsg,
    ];
    setMessages([...withoutSystem, userMsg]);

    try {
      const { transcript: full, error } = await runAgenticTurn(transcript, {
        signal: ac.signal,
      });
      const forUi = withStableIds(full.filter((m) => m.role !== "system"));
      setMessages(forUi);
      if (error) setStatus(error);
    } finally {
      if (runAbortRef.current === ac) runAbortRef.current = null;
      setBusy(false);
      await loadAudit();
      await refreshWorkspace();
    }
  };

  const onClearChat = () => {
    cancelMessageEdit();
    setMessages([]);
    setPendingUploads([]);
    setStatus(null);
    localStorage.removeItem("bacongris_autosave");
    void (async () => {
      try {
        await invoke("save_conversation", { messages: [] });
      } catch {
        /* no tauri */
      }
    })();
  };

  const onImportLegacy = useCallback(async () => {
    const raw = localStorage.getItem("bacongris_autosave");
    if (!raw) {
      setImportModalOpen(false);
      return;
    }
    try {
      const p = JSON.parse(raw) as { messages?: OllamaMessage[] };
      const m = p.messages ?? [];
      await invoke("import_local_storage_conversation", { messages: m });
      localStorage.removeItem("bacongris_autosave");
      setImportModalOpen(false);
      sessionStorage.setItem("bacongris_v2_import_dismissed", "1");
      setStatus(`Imported ${m.length} message(s) into the active agent.`);
      await loadProfilesAgentsAndContext();
      await loadConversationFromDisk();
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  }, [loadConversationFromDisk, loadProfilesAgentsAndContext]);

  const onDismissImport = useCallback(() => {
    setImportModalOpen(false);
    sessionStorage.setItem("bacongris_v2_import_dismissed", "1");
  }, []);

  const onSelectProfile = useCallback(
    async (profileId: string) => {
      try {
        await invoke("set_active_profile_id", { profileId });
        setAppStateV2((s) =>
          s ? { ...s, activeProfileId: profileId, activeAgentId: null } : s,
        );
        await loadProfilesAgentsAndContext();
        await refreshWorkspace();
        setMessages([]);
        await loadConversationFromDisk();
        const ex = await invoke<{
          userRules: string;
          memoryExcerpt: string;
          preferencesExcerpt?: string;
        }>("get_llm_context_extras");
        setPromptExtras({
          userRules: ex.userRules,
          memoryExcerpt: ex.memoryExcerpt,
          preferencesExcerpt: ex.preferencesExcerpt ?? "",
        });
      } catch (e) {
        setStatus(e instanceof Error ? e.message : String(e));
      }
    },
    [loadConversationFromDisk, loadProfilesAgentsAndContext, refreshWorkspace],
  );

  const onSelectAgent = useCallback(
    async (agentId: string) => {
      try {
        await invoke("set_active_agent_id", { agentId });
        setAppStateV2((s) => (s ? { ...s, activeAgentId: agentId } : s));
        setMessages([]);
        await loadConversationFromDisk();
      } catch (e) {
        setStatus(e instanceof Error ? e.message : String(e));
      }
    },
    [loadConversationFromDisk],
  );

  const openNewAgentModal = useCallback(() => {
    setNewAgentTitleDraft("Chat");
    setNewAgentOpen(true);
  }, []);

  const confirmNewAgent = useCallback(async () => {
    const title = newAgentTitleDraft.trim() || "Chat";
    setNewAgentOpen(false);
    setStatus(null);
    try {
      const a = await invoke<AgentInfo>("create_agent", { title });
      setAgents((list) => [a, ...list]);
      setAppStateV2((s) => (s ? { ...s, activeAgentId: a.id } : s));
      setMessages([]);
      await loadConversationFromDisk();
      setStatus("New agent created.");
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  }, [newAgentTitleDraft, loadConversationFromDisk]);

  const onAddWorkspace = useCallback(async () => {
    const choice = await open({
      directory: true,
      multiple: false,
      title: "Add workspace (folder on disk)",
    });
    const path =
      typeof choice === "string"
        ? choice
        : Array.isArray(choice) && choice[0]
          ? choice[0]
          : null;
    if (!path) return;
    const name =
      path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || "Workspace";
    try {
      const prof = await invoke<WorkspaceProfile>("create_workspace_profile", {
        name,
        path,
      });
      setWorkspaceProfiles((prev) => [prof, ...prev]);
      setAppStateV2({
        activeProfileId: prof.id,
        activeAgentId: null,
      });
      setMessages([]);
      await loadProfilesAgentsAndContext();
      await refreshWorkspace();
      const ex = await invoke<{
        userRules: string;
        memoryExcerpt: string;
        preferencesExcerpt?: string;
      }>("get_llm_context_extras");
      setPromptExtras({
        userRules: ex.userRules,
        memoryExcerpt: ex.memoryExcerpt,
        preferencesExcerpt: ex.preferencesExcerpt ?? "",
      });
      await loadConversationFromDisk();
      setStatus(`Switched to workspace: ${name}`);
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  }, [loadConversationFromDisk, loadProfilesAgentsAndContext, refreshWorkspace]);

  const replaceToolResultAndContinue = useCallback(
    async (d: RunCommandDenied, newContent: string, runSignal?: AbortSignal) => {
      const ac = runSignal ? null : new AbortController();
      if (ac) runAbortRef.current = ac;
      const withoutSystem = messages.filter((m) => m.role !== "system");
      const newMsgs = [...withoutSystem];
      if (newMsgs[d.toolMessageIndex]?.role === "tool") {
        newMsgs[d.toolMessageIndex] = {
          ...newMsgs[d.toolMessageIndex],
          content: newContent,
        };
      }
      const transcript: OllamaMessage[] = [systemMessage, ...newMsgs];
      const signal = runSignal ?? ac!.signal;
      try {
        const { transcript: full, error } = await runAgenticTurn(transcript, {
          signal,
        });
        const forUi = withStableIds(full.filter((m) => m.role !== "system"));
        setMessages(forUi);
        if (error) setStatus(error);
      } finally {
        if (ac && runAbortRef.current === ac) runAbortRef.current = null;
      }
    },
    [messages, systemMessage],
  );

  const onAllowOnceAndRetryRun = useCallback(async () => {
    const d = runCommandDenial;
    if (!d || busy) return;
    const ac = new AbortController();
    runAbortRef.current = ac;
    setBusy(true);
    setStatus(null);
    try {
      await invoke("session_allow_for_program", {
        program: d.requested,
        suggested_path: d.suggestedPath || null,
      });
      const result = await invoke<unknown>("run_command", {
        program: d.program,
        args: d.args,
        cwd: d.cwd,
      });
      await replaceToolResultAndContinue(
        d,
        JSON.stringify(result, null, 2),
        ac.signal,
      );
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    } finally {
      if (runAbortRef.current === ac) runAbortRef.current = null;
      setBusy(false);
      void loadAudit();
    }
  }, [
    runCommandDenial,
    busy,
    replaceToolResultAndContinue,
    loadAudit,
  ]);

  const onAddSuggestedToAllowlist = useCallback(async () => {
    const d = runCommandDenial;
    if (!d) return;
    const line = (d.suggestedPath || "").trim();
    if (!line) {
      setStatus(
        "No suggested full path. Open Settings and add the binary path (e.g. output of `which program`), then use Run again (saved list).",
      );
      setSettingsOpen(true);
      return;
    }
    if (settings.allowedExecutables.includes(line)) {
      setStatus("That path is already in Allowed executables.");
      return;
    }
    const next: AppSettings = {
      ...settings,
      allowedExecutables: [...settings.allowedExecutables, line],
    };
    try {
      await persistSettings(next);
      setExecText(rootsToText(next.allowedExecutables));
      setStatus('Saved. Use "Run again (saved allowlist)" to continue (no one-shot allow needed).');
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    }
  }, [runCommandDenial, settings]);

  const onRetryRunWithSavedAllowlist = useCallback(async () => {
    const d = runCommandDenial;
    if (!d || busy) return;
    const ac = new AbortController();
    runAbortRef.current = ac;
    setBusy(true);
    setStatus(null);
    try {
      const result = await invoke<unknown>("run_command", {
        program: d.program,
        args: d.args,
        cwd: d.cwd,
      });
      await replaceToolResultAndContinue(
        d,
        JSON.stringify(result, null, 2),
        ac.signal,
      );
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    } finally {
      if (runAbortRef.current === ac) runAbortRef.current = null;
      setBusy(false);
      void loadAudit();
    }
  }, [runCommandDenial, busy, replaceToolResultAndContinue, loadAudit]);

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
          <div className="workspace-panel-pinned">
            <h2 className="workspace-title">Workspace</h2>
            <p className="workspace-path" title={workspace?.effectivePath ?? ""}>
              {workspace ? workspace.effectivePath : "…"}
            </p>
            {workspace && !workspace.pathAccessible && workspace.pathError && (
              <p className="workspace-path-warn" title={workspace.pathError}>
                {workspace.pathError}
              </p>
            )}
            <div className="workspace-profile-row">
              <label className="field-inline">
                <span>Profile</span>
                <select
                  value={appStateV2?.activeProfileId ?? ""}
                  onChange={(e) => void onSelectProfile(e.target.value)}
                  disabled={!workspaceProfiles.length}
                >
                  {workspaceProfiles.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                className="btn small"
                onClick={() => void onAddWorkspace()}
              >
                Add workspace
              </button>
            </div>
            <div className="workspace-profile-row">
              <label className="field-inline">
                <span>Agent</span>
                <select
                  value={appStateV2?.activeAgentId ?? ""}
                  onChange={(e) => void onSelectAgent(e.target.value)}
                  disabled={!agents.length}
                >
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.title}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                className="btn small"
                onClick={() => openNewAgentModal()}
              >
                New agent
              </button>
            </div>
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
          </div>
          <div className="workspace-panel-body">
            <p className="workspace-hint">
              Scripts live in <code>scripts/</code> inside this folder (allowlisted for
              tools).               On first open, <code>venv_run.sh</code> and <code>bacongris_smoke_test.py</code>{" "}
              are created there. The smoke script is a no-network dummy you can use to test: run
              it with <code>run_command</code> and an email arg; stdout is JSON the model can
              read. From the workspace root:{" "}
              <code>python3 scripts/bacongris_smoke_test.py you@example.com</code> (add{" "}
              <code>python3</code> to Allowed executables if needed).
            </p>
            <div className="workspace-ioc-activity">
              <div className="workspace-ioc-activity-head">
                <span className="workspace-files-head">Recent IOCs (last seen)</span>
                <div className="workspace-side-actions">
                  <button
                    type="button"
                    className="btn small ghost"
                    title="Refresh recent IOCs and feed health"
                    onClick={() => void refreshSidePanelCti()}
                  >
                    Refresh
                  </button>
                  <button
                    type="button"
                    className="btn small ghost"
                    disabled={busy}
                    title="Insert a triage prompt into the chat (edit, then Send)"
                    onClick={() => insertLatestIocTriagePrompt()}
                  >
                    Triage in chat
                  </button>
                </div>
              </div>
              {iocActivityErr && (
                <p className="field-help">{iocActivityErr}</p>
              )}
              {iocActivity && iocActivity.length === 0 && !iocActivityErr && (
                <p className="muted">No stored IOCs for this profile scope yet.</p>
              )}
              {iocActivity && iocActivity.length > 0 && (
                <ul className="workspace-ioc-list">
                  {iocActivity.map((r) => (
                    <li key={r.id} title={r.id}>
                      <div className="workspace-ioc-line1">
                        <span>
                          <span className="workspace-ioc-type">{r.iocType}</span>{" "}
                          <code className="workspace-ioc-val">{r.value}</code>
                        </span>
                        <span className="workspace-ioc-time">
                          {new Date(r.lastSeen * 1000).toLocaleString(undefined, {
                            dateStyle: "short",
                            timeStyle: "short",
                          })}
                        </span>
                      </div>
                      {r.source != null && String(r.source).trim() !== "" && (
                        <span className="workspace-ioc-source" title="Source / feed label">
                          {r.source}
                        </span>
                      )}
                      {r.mitreTechniques.length > 0 && (
                        <span className="workspace-ioc-mitre">
                          {r.mitreTechniques.join(" · ")}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="workspace-feed-health">
              <div className="workspace-ioc-activity-head">
                <span className="workspace-files-head">Feed health</span>
              </div>
              {feedHealthErr && (
                <p className="field-help">{feedHealthErr}</p>
              )}
              {feedHealth && feedHealth.length === 0 && !feedHealthErr && (
                <p className="muted">No feeds configured. Use the agent (add_feed) or wire feeds in a future settings panel.</p>
              )}
              {feedHealth && feedHealth.length > 0 && (
                <ul className="workspace-ioc-list workspace-feed-health-list">
                  {feedHealth.map((r) => (
                    <li key={r.feedId} title={r.feedId}>
                      <div className="workspace-ioc-line1">
                        <span>
                          <span className="workspace-ioc-type">{r.ftype}</span>{" "}
                          <span className="workspace-feed-name">{r.name}</span>
                          {r.enabled === 0 && (
                            <span className="workspace-feed-pill off">off</span>
                          )}
                          {r.isUnhealthy && r.enabled === 1 && (
                            <span className="workspace-feed-pill bad">unhealthy</span>
                          )}
                          {!r.isUnhealthy && r.enabled === 1 && (
                            <span className="workspace-feed-pill ok">ok</span>
                          )}
                        </span>
                        <span className="workspace-ioc-time" title="Last successful poll">
                          {r.lastPollTime
                            ? new Date(r.lastPollTime * 1000).toLocaleString(undefined, {
                                dateStyle: "short",
                                timeStyle: "short",
                              })
                            : "—"}
                        </span>
                      </div>
                      {(r.lastError || (r.stalenessSeconds != null && r.isStale)) && (
                        <div className="workspace-feed-meta">
                          {r.lastError && (
                            <span className="workspace-feed-err" title="Last error">
                              {r.lastError}
                            </span>
                          )}
                          {r.stalenessSeconds != null && r.isStale && r.pollIntervalMinutes && (
                            <span className="workspace-feed-stale" title="Staleness vs poll interval (1.5x)">
                              {Math.floor(r.stalenessSeconds / 60)}m since last success (interval {r.pollIntervalMinutes}m)
                            </span>
                          )}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
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
          {runCommandDenial && (
            <div className="denial-panel" role="region" aria-label="Command blocked">
              <div className="denial-title">A run was blocked (executable not allowlisted)</div>
              <p className="denial-reason">
                <code>{runCommandDenial.requested}</code> — {runCommandDenial.reason}
              </p>
              {runCommandDenial.suggestedPath && (
                <p className="denial-suggest">
                  Suggested path: <code>{runCommandDenial.suggestedPath}</code>
                </p>
              )}
              <div className="denial-actions">
                <button
                  type="button"
                  className="btn small primary"
                  disabled={busy}
                  onClick={() => void onAllowOnceAndRetryRun()}
                >
                  Allow once &amp; continue
                </button>
                <button
                  type="button"
                  className="btn small"
                  disabled={busy}
                  onClick={() => void onAddSuggestedToAllowlist()}
                >
                  Add suggested path to Settings
                </button>
                <button
                  type="button"
                  className="btn small ghost"
                  disabled={busy}
                  onClick={() => void onRetryRunWithSavedAllowlist()}
                >
                  Run again (saved allowlist)
                </button>
              </div>
            </div>
          )}
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="sr-only"
            title="Add files (fallback if system picker is unavailable)"
            onChange={(e) => void onFileInputChange(e)}
          />
          {pendingUploads.length > 0 && (
            <div className="composer-attachments" aria-label="Files to send">
              {pendingUploads.map((u) => (
                <span key={u.path} className="upload-chip" title={u.path}>
                  <code>{u.name}</code>
                  <span>
                    {u.size.toLocaleString()} B
                  </span>
                  <button
                    type="button"
                    aria-label={`Remove ${u.name}`}
                    onClick={() =>
                      setPendingUploads((p) => p.filter((x) => x.path !== u.path))
                    }
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="composer-row">
            <textarea
              ref={composerInputRef}
              className="input"
              rows={3}
              placeholder="Message the agent (optional if you attached files)…"
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
            <div className="composer-actions">
            {busy && (
              <button
                type="button"
                className="btn"
                onClick={onCancelRun}
                title="Stop the agent and any in-flight run_command subprocess"
              >
                Stop
              </button>
            )}
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={() => void onAttachFiles()}
              title="Add files to the workspace for analysis (saved under uploads/)"
            >
              Attach
            </button>
            <button
              type="button"
              className="btn primary"
              disabled={busy || (!input.trim() && !pendingUploads.length)}
              onClick={() => void onSend()}
            >
              Send
            </button>
            </div>
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

            <section className="settings-section">
              <h3>CTI / API keys and rate limits</h3>
              <p className="field-help">
                Stored in app settings (plain text). Keys are merged with{" "}
                <code>~/.config/…/BacongrisCTIAgent/.api_keys.json</code> (file wins
                on duplicate names). Use lowercase API names (e.g.{" "}
                <code>virustotal</code>, <code>shodan</code>).
              </p>
              <label className="field">
                <span>apiKeys (JSON object, string values)</span>
                <textarea
                  rows={5}
                  spellCheck={false}
                  value={apiKeysText}
                  onChange={(e) => setApiKeysText(e.target.value)}
                />
              </label>
              <label className="field">
                <span>apiRateLimits (JSON object per API name)</span>
                <textarea
                  rows={6}
                  spellCheck={false}
                  value={apiRateLimitsText}
                  onChange={(e) => setApiRateLimitsText(e.target.value)}
                  placeholder='e.g. { "virustotal": { "requestsPerMinute": 4, "requestsPerDay": 1000, "cacheTtlSecs": 300 } }'
                />
              </label>
            </section>

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

            <section className="settings-section">
              <h3>Command sandbox (Docker)</h3>
              <p className="field-help">
                When enabled, model-invoked <code>run_command</code> runs inside{" "}
                <code>docker run</code> (no default network, cwd bind-mounted to{" "}
                <code>/workspace</code>). Requires Docker installed and the image
                pulled (e.g. <code>python:3.12-slim</code>).
              </p>
              <label className="field field-check">
                <input
                  type="checkbox"
                  checked={settings.useDockerSandbox}
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      useDockerSandbox: e.target.checked,
                    }))
                  }
                />
                <span>Run tool commands in Docker sandbox</span>
              </label>
              <label className="field">
                <span>Docker image</span>
                <input
                  value={settings.dockerSandboxImage}
                  placeholder="python:3.12-slim"
                  onChange={(e) =>
                    setSettings((s) => ({
                      ...s,
                      dockerSandboxImage: e.target.value,
                    }))
                  }
                />
              </label>
            </section>

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

      {newAgentOpen && (
        <div
          className="import-backdrop"
          role="presentation"
          onClick={() => setNewAgentOpen(false)}
        >
          <div
            className="import-modal"
            role="dialog"
            aria-label="New agent"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>New agent</h3>
            <p>Choose a title for this chat thread. It is stored in the app database for the current workspace profile.</p>
            <label className="field new-agent-title-field">
              <span>Name</span>
              <input
                type="text"
                autoFocus
                value={newAgentTitleDraft}
                onChange={(e) => setNewAgentTitleDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void confirmNewAgent();
                  }
                }}
                placeholder="Chat"
              />
            </label>
            <div className="import-modal-actions new-agent-modal-actions">
              <button
                type="button"
                className="btn primary"
                onClick={() => void confirmNewAgent()}
              >
                Create
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={() => setNewAgentOpen(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {importModalOpen && (
        <div
          className="import-backdrop"
          role="presentation"
          onClick={onDismissImport}
        >
          <div
            className="import-modal"
            role="dialog"
            aria-label="Import chat from browser"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>Import previous chat from browser storage?</h3>
            <p>
              A legacy autosave was found. You can import it into the
              <strong> active profile agent</strong> (on-disk store). Your first
              profile was created from Settings if needed.
            </p>
            <div className="import-modal-actions">
              <button
                type="button"
                className="btn primary"
                onClick={() => void onImportLegacy()}
              >
                Import
              </button>
              <button
                type="button"
                className="btn ghost"
                onClick={onDismissImport}
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
