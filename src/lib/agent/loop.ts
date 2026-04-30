import { invoke } from "@tauri-apps/api/core";
import type { OllamaMessage, OllamaToolCall } from "./types";
import { getOllamaTools } from "./tools";
import { agentLog, agentWarn, summarizeOllamaToolCalls } from "./agentDebug";
import {
  canonicalizeHallucinatedToolName,
  tryExtractBashFictionSendTerminal,
  tryExtractToolCallsFromText,
  tryRepairRunToolToTerminal,
} from "./toolCallFallback";
import {
  coerceCwdArg,
  coerceFileContentArg,
  coercePathArg,
  isBareWorkspaceReadmePath,
  resolveRunCommandProgramAndArgv,
  coerceTerminalDataArg,
  ensurePtyLineSubmitted,
  normalizeTerminalEscapeLiterals,
  preferPython3Command,
  parseAnalyzeWorkspaceCallArgs,
  parseToolArguments,
  parseIocSearchArgs,
  parseIocStringFields,
  pickOptString,
  coerceTrustedWorkflowArg,
  coerceTrustedWorkflowQueryArg,
  coerceIntelxStartDateArg,
  coerceIntelxEndDateArg,
  coerceIntelxSearchLimitArg,
  coerceCveStartDateArg,
  coerceCveEndDateArg,
  coerceCveCvssArg,
  coerceCveCvssV4Arg,
  terminalTextFromRunCommandStyleArgs,
} from "./toolArgs";
import { normalizeToolCallsForWire, prepareForOllamaRequest } from "./ollamaMessages";
import { isWorkflowCatalogQuestion } from "./routingHints";
import { preFlightCheck } from "./OllamaClient";
import { scheduleCveVaultSyncToAppDb } from "../ctiVaultSync";

function pickRawJsonArg(args: Record<string, unknown>): string | undefined {
  const keys = ["raw_json", "rawJson", "raw"];
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "string") return v;
  }
  return undefined;
}

function parseOptInt(v: unknown): number | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === "string" && v.trim() !== "" && /^-?\d+$/.test(v.trim())) {
    return parseInt(v.trim(), 10);
  }
  return undefined;
}

function parseOptI64Num(
  args: Record<string, unknown>,
  keys: string[],
): number | undefined {
  for (const k of keys) {
    const v = args[k];
    if (v === null || v === undefined) continue;
    if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
    if (typeof v === "string" && v.trim() !== "" && /^-?\d+$/.test(v.trim())) {
      return parseInt(v.trim(), 10);
    }
  }
  return undefined;
}

/** MITRE T#### / T####.### / TA####; JSON array, comma list, or single id. */
function parseMitreListArg(
  args: Record<string, unknown>,
): string[] | undefined {
  const v = args["mitre_techniques"] ?? args["mitreTechniques"] ?? args["mitre"];
  if (v === null || v === undefined) return undefined;
  if (Array.isArray(v)) {
    const s = v.map((x) => String(x).trim()).filter(Boolean);
    return s.length ? s : [];
  }
  if (typeof v === "string") {
    const t = v.trim();
    if (!t) return undefined;
    try {
      const j: unknown = JSON.parse(t);
      if (Array.isArray(j)) {
        const s = j.map((x) => String(x).trim()).filter(Boolean);
        return s.length ? s : [];
      }
    } catch {
      /* not JSON */
    }
    return t.split(/[\s,]+/).filter(Boolean);
  }
  return undefined;
}

/** Ollama may reject unknown fields; omit UI-only keys. */

/** Strip client-only keys; sanitize for Ollama /api/chat (see `ollamaMessages.ts`). */
function messageForApi(m: OllamaMessage): OllamaMessage {
  return prepareForOllamaRequest(m);
}

/**
 * Most recent user **typed** text (excludes merged file contents). Used for routing
 * (e.g. workflow catalog checks). File bodies are only in `prepareForOllamaRequest` merge.
 */
function getLastUserMessageText(msgs: OllamaMessage[]): string {
  for (let i = msgs.length - 1; i >= 0; i -= 1) {
    if (msgs[i].role === "user") {
      const c = msgs[i].content;
      if (typeof c === "string" && c.trim() !== "") return c;
    }
  }
  return "";
}

function prependStaleWarningToLastAssistant(
  msgs: OllamaMessage[],
  warning: string | undefined,
): void {
  if (!warning) return;
  for (let i = msgs.length - 1; i >= 0; i -= 1) {
    if (msgs[i].role === "assistant") {
      const c = msgs[i].content;
      const t = typeof c === "string" ? c : "";
      if (t.startsWith(warning)) return;
      const next = t ? `${warning}\n\n${t}` : warning;
      msgs[i] = { ...msgs[i], content: next };
      return;
    }
  }
}

/** If the model emitted tool calls *and* long prose, keep prose out of the main chat (collapsible). */
const ASSISTANT_COT_COLLAPSE_MIN_LEN = 320;

function extractAssistantMessage(res: Record<string, unknown>): OllamaMessage {
  const message = res.message as Record<string, unknown> | undefined;
  if (!message || typeof message !== "object") {
    return { role: "assistant", content: JSON.stringify(res) };
  }
  const role = (message.role as string) || "assistant";
  let content =
    typeof message.content === "string" ? message.content : undefined;
  let tool_calls = message.tool_calls as OllamaToolCall[] | undefined;
  const hadApiToolCalls = Boolean(tool_calls?.length);
  const apiThinking =
    typeof (message as { thinking?: unknown }).thinking === "string"
      ? (message as { thinking: string }).thinking
      : undefined;
  // qwen3-vl: `thinking` may hold tool JSON while `content` is empty. Merge **only** when the API
  // did not already send `tool_calls`—otherwise the monologue would duplicate in chat next to tools.
  if (!hadApiToolCalls && (!content || !String(content).trim()) && apiThinking?.trim()) {
    agentLog(
      "assistant: merge thinking into content for extraction (content empty, no API tool_calls)",
      apiThinking.length,
      "chars",
    );
    content = apiThinking;
  }
  // Some local models return tool JSON in `content` but omit `tool_calls` — run tools anyway.
  if (!tool_calls?.length && content) {
    const fallback = tryExtractToolCallsFromText(content);
    if (fallback?.length) {
      agentLog("toolCallFallback: parsed JSON in content →", fallback.length, "synthetic call(s)", summarizeOllamaToolCalls(fallback));
      tool_calls = fallback;
      content = "";
    }
  }
  // Models that write ```bash send_integrated_terminal "cd ..."``` instead of real tool_calls.
  if (!tool_calls?.length && content) {
    const shim = tryExtractBashFictionSendTerminal(content);
    if (shim) {
      agentLog("toolCallFallback: bash-fiction send_integrated_terminal → synthetic call");
      tool_calls = [shim];
    }
  }
  if (!hadApiToolCalls && !tool_calls?.length && content) {
    agentLog("assistant: no tool_calls and no fallback; content length", content.length, "preview:", content.slice(0, 300));
  }

  const hasTools = Boolean(tool_calls?.length);
  let thinking: string | undefined;
  if (hasTools) {
    const c = (content ?? "").trim();
    if (c.length >= ASSISTANT_COT_COLLAPSE_MIN_LEN) {
      thinking = c;
      if (apiThinking?.trim()) {
        thinking = `${c}\n\n---\n\n${apiThinking.trim()}`;
      }
      content = "";
    } else if (apiThinking && apiThinking.trim().length >= ASSISTANT_COT_COLLAPSE_MIN_LEN) {
      // Short (or empty) `content` but long `thinking` channel — keep the short line in chat, hide monologue
      thinking = apiThinking.trim();
    } else if (c.length === 0 && apiThinking?.trim()) {
      thinking = apiThinking.trim();
      content = undefined;
    }
  }

  if (tool_calls?.length) {
    tool_calls = normalizeToolCallsForWire(tool_calls);
  }

  const out: OllamaMessage = {
    role: role as "assistant",
    content,
    tool_calls,
  };
  if (thinking) {
    out.thinking = thinking;
  }
  return out;
}

const CANCELLED_JSON = JSON.stringify({ error: "Run cancelled by user." });

function toolMsgCancelled(
  name: string,
  tc: OllamaToolCall,
): OllamaMessage {
  return {
    role: "tool",
    content: CANCELLED_JSON,
    tool_name: name,
    name,
    tool_call_id: tc.id,
  };
}

async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
  signal: AbortSignal | undefined,
): Promise<string> {
  if (signal?.aborted) {
    return CANCELLED_JSON;
  }
  const argKeys = Object.keys(args);
  agentLog("dispatchTool", name, "argKeys:", argKeys);
  try {
    switch (name) {
      case "get_environment": {
        const env = await invoke<unknown>("get_environment");
        return JSON.stringify(env, null, 2);
      }
      case "read_text_file": {
        const path = coercePathArg(args);
        if (!path) {
          return JSON.stringify({
            error:
              "Missing path. Pass path as a string (absolute path under your workspace). If the model sent arguments as nested JSON, it is normalized — try again with path only.",
          });
        }
        if (isBareWorkspaceReadmePath(path)) {
          return JSON.stringify({
            error:
              "Bare `README.md` resolves to the workspace root, which often has no such file. Use the project-relative path from **get_environment** / the workspace index (e.g. `CVE_Project_NVD/README.md`). Call **list_directory** on the project folder if unsure.",
          });
        }
        const text = await invoke<string>("read_text_file", { path });
        return text;
      }
      case "write_text_file": {
        const path = coercePathArg(args);
        if (!path) {
          return JSON.stringify({
            error:
              "Missing path. Pass path as a string (absolute file path under the workspace or allowlisted roots).",
          });
        }
        const content = coerceFileContentArg(args);
        const w = await invoke<unknown>("write_text_file", { path, content });
        return JSON.stringify(w, null, 2);
      }
      case "list_directory": {
        let path = coercePathArg(args);
        if (!path || !path.trim()) {
          path = ".";
        }
        if (isBareWorkspaceReadmePath(path)) {
          return JSON.stringify({
            error:
              "Bare `README.md` is not a directory. Use a folder path (e.g. `Ransomware_live_event_victim` or `Ransomware_live_event_victim/`) then **read_text_file** on that project’s `README.md`.",
          });
        }
        const rows = await invoke<unknown>("list_directory", { path: path.trim() });
        return JSON.stringify(rows, null, 2);
      }
      case "analyze_workspace_run_requirements": {
        const a = parseAnalyzeWorkspaceCallArgs(args);
        const report = await invoke<unknown>("analyze_workspace_run_requirements", {
          workflow_relative_path: a.workflowRelativePath,
          full_workspace: a.fullWorkspace,
          use_cache: a.useCache,
        });
        return JSON.stringify(report, null, 2);
      }
      case "run_trusted_workflow": {
        const workflow = coerceTrustedWorkflowArg(args);
        if (!workflow) {
          return JSON.stringify({
            error:
              "Missing workflow. Pass workflow: \"intelx\" | \"cve\" | \"cve_nvd\" | \"ransomware\" | \"asm_fetch\" | \"social_mediav2\" | \"phishing_social\" | \"iocs_crawler\" | \"compromised_mac\" (see scripts/cti_workflows.json for aliases).",
          });
        }
        const queryRaw = coerceTrustedWorkflowQueryArg(args);
        const query = queryRaw.trim() || null;
        const isd = coerceIntelxStartDateArg(args).trim() || null;
        const ied = coerceIntelxEndDateArg(args).trim() || null;
        const isl = coerceIntelxSearchLimitArg(args).trim() || null;
        const cveSd = coerceCveStartDateArg(args).trim() || null;
        const cveEd = coerceCveEndDateArg(args).trim() || null;
        const cveCs = coerceCveCvssArg(args).trim() || null;
        const cveCsV4 = coerceCveCvssV4Arg(args).trim() || null;
        const wfNorm = workflow
          .trim()
          .toLowerCase()
          .replace(/-/g, "_")
          .replace(/\s+/g, "_");
        const isCveWorkflow =
          wfNorm === "cve" || wfNorm === "cve_nvd" || wfNorm === "nvd";
        const result = await invoke<unknown>("run_trusted_workflow", {
          workflow,
          query,
          intelx_start_date: isd,
          intelx_end_date: ied,
          intelx_search_limit: isl,
          cve_start_date: cveSd,
          cve_end_date: cveEd,
          cve_cvss: cveCs,
          cve_cvss_v4: cveCsV4,
        });
        if (isCveWorkflow) {
          scheduleCveVaultSyncToAppDb();
        }
        if (result && typeof result === "object" && !Array.isArray(result)) {
          return JSON.stringify(
            {
              ...(result as Record<string, unknown>),
              ...(isCveWorkflow
                ? {
                    ctiVaultToAppIocSync: "scheduled",
                    ctiVaultToAppIocSyncHint:
                      "Queued merges from workspace `cti_vault.db` (`cve_data`) into the app `iocs` table (immediate + 8s + 45s). Long NVD runs may finish later — call **sync_cti_vault_cves_to_iocs** again, then **ioc_search** with `ioc_type: \"cve\"`.",
                  }
                : {}),
            },
            null,
            2,
          );
        }
        return JSON.stringify(result, null, 2);
      }
      case "sync_cti_vault_cves_to_iocs": {
        const lim = parseOptI64Num(args, ["limit", "row_limit", "maxRows"]);
        const out = await invoke<unknown>("sync_cti_vault_cves_to_iocs", {
          limit: lim != null ? lim : null,
        });
        return JSON.stringify(out, null, 2);
      }
      case "run_command":
      case "run":
      case "run_terminal": {
        const resolved = resolveRunCommandProgramAndArgv(args);
        if (!resolved) {
          return JSON.stringify({
            error:
              "Missing **program** + **args**, or a shell line in **cmd** / **text**. Examples: `program` \"python3\", `args` [\"-c\",\"print(1)\"]; or `cmd` \"ls -la\" (runs as bash -c); for Docker Compose v2: `program` \"docker\", `args` [\"compose\",\"-f\",composeFile,\"up\",...].",
          });
        }
        const { program, argv } = resolved;
        const cwd = coerceCwdArg(args);
        if (signal?.aborted) {
          return CANCELLED_JSON;
        }
        const result = await invoke<unknown>("run_command", {
          program,
          args: argv,
          cwd,
        });
        if (signal?.aborted) {
          return CANCELLED_JSON;
        }
        return JSON.stringify(result, null, 2);
      }
      case "terminal_output": {
        return JSON.stringify(
          {
            ok: false,
            note: "The host does not stream the integrated terminal to the model. Use list_directory and read_text_file on workspace outputs (e.g. Intelx_Crawler/csv_output/), or ask the user to paste from the bottom panel. To start IntelX use run_trusted_workflow with workflow \"intelx\" and an optional query—do not use run() with program \"intelx\" (not a binary).",
          },
          null,
          2,
        );
      }
      case "send_integrated_terminal": {
        let raw = coerceTerminalDataArg(args);
        if (!raw) {
          const fromRc = terminalTextFromRunCommandStyleArgs(args);
          if (fromRc) {
            agentLog(
              "send_integrated_terminal: synthesized text from program+args (model used run_command shape)",
            );
            raw = fromRc;
          }
        }
        if (!raw) {
          return JSON.stringify({
            error:
              "Missing **text** (or **data**) to send. This tool is not `run_command`: do not pass `program`+`args` alone—put the full line in **text** (e.g. `cd CVE_Project_NVD && python3 main.py`).",
          });
        }
        const data = ensurePtyLineSubmitted(
          preferPython3Command(normalizeTerminalEscapeLiterals(raw)),
        );
        const cwd = coerceCwdArg(args);
        await invoke("terminal_ensure_write", {
          data,
          cwd,
        });
        return JSON.stringify({
          ok: true,
          message:
            "Text was sent to the integrated terminal. Watch the bottom panel for output; stdout/stderr is not returned to chat.",
        });
      }
      case "system_maintenance_status": {
        const { MaintenanceManager } = await import("../maintenance");
        const state = await MaintenanceManager.getState();
        return JSON.stringify(state, null, 2);
      }
      case "ioc_create": {
        const f = parseIocStringFields(args);
        const value =
          typeof args.value === "string"
            ? args.value
            : f.value;
        if (!value || !String(value).trim()) {
          return JSON.stringify({
            error: "ioc_create requires **value** (the IOC string) and **ioc_type** (e.g. ipv4, domain, sha256).",
          });
        }
        const iocType =
          f.iocType ??
          (typeof args.ioc_type === "string" ? args.ioc_type : undefined) ??
          (typeof args.type === "string" ? args.type : undefined);
        if (!iocType || !String(iocType).trim()) {
          return JSON.stringify({ error: "ioc_create requires **ioc_type** (e.g. ipv4, sha256, domain, url)." });
        }
        const conf =
          typeof args.confidence === "number" && Number.isFinite(args.confidence)
            ? Math.trunc(args.confidence)
            : undefined;
        const fpU =
          typeof args["is_false_positive"] === "boolean"
            ? args["is_false_positive"]
            : typeof args["isFalsePositive"] === "boolean"
              ? args["isFalsePositive"]
              : undefined;
        const mlist = parseMitreListArg(args);
        const row = await invoke<unknown>("ioc_create", {
          value: String(value).trim(),
          ioc_type: String(iocType).trim(),
          source: f.source,
          confidence: conf,
          campaign_tag: f.campaignTag,
          raw_json: pickRawJsonArg(args),
          profile_id: f.profileId,
          valid_until: parseOptI64Num(args, ["valid_until", "validUntil"]),
          is_false_positive: fpU,
          mitre_techniques: mlist,
        });
        return JSON.stringify(row, null, 2);
      }
      case "ioc_search": {
        const s = parseIocSearchArgs(args);
        const rows = await invoke<unknown>("ioc_search", {
          value_contains: s.valueContains,
          ioc_type: s.iocType,
          campaign: s.campaign,
          source: s.source,
          profile_id: s.profileId,
          all_profiles: s.allProfiles,
          include_false_positives: s.includeFalsePositives,
          limit: s.limit,
        });
        return JSON.stringify(rows, null, 2);
      }
      case "ioc_update": {
        const f = parseIocStringFields(args);
        if (!f.id) {
          return JSON.stringify({ error: "ioc_update requires **id** of the stored IOC." });
        }
        const clearVu =
          args["clear_valid_until"] === true ||
          args["clearValidUntil"] === true;
        const fpB =
          typeof args["is_false_positive"] === "boolean"
            ? (args["is_false_positive"] as boolean)
            : typeof args["isFalsePositive"] === "boolean"
              ? (args["isFalsePositive"] as boolean)
              : undefined;
        const n = await invoke<unknown>("ioc_update", {
          id: f.id,
          value: f.value,
          ioc_type: f.iocType,
          source: f.source,
          confidence: parseOptInt(args["confidence"]),
          campaign_tag: f.campaignTag,
          first_seen: parseOptI64Num(args, ["first_seen", "firstSeen"]),
          last_seen: parseOptI64Num(args, ["last_seen", "lastSeen"]),
          raw_json: pickRawJsonArg(args),
          valid_until: clearVu
            ? undefined
            : parseOptI64Num(args, ["valid_until", "validUntil"]),
          clear_valid_until: clearVu ? true : undefined,
          is_false_positive: fpB,
          mitre_techniques: parseMitreListArg(args),
        });
        return JSON.stringify(n, null, 2);
      }
      case "ioc_delete": {
        const f = parseIocStringFields(args);
        if (!f.id) {
          return JSON.stringify({ error: "ioc_delete requires **id**." });
        }
        await invoke("ioc_delete", { id: f.id });
        return JSON.stringify({ ok: true, id: f.id });
      }
      case "ioc_import_stix": {
        const f = parseIocStringFields(args);
        const j = f.json;
        if (!j || !j.trim()) {
          return JSON.stringify({
            error: "Pass **json** (full STIX 2.x bundle or object as a string).",
          });
        }
        const r = await invoke<unknown>("ioc_import_stix", {
          json: j,
          source: f.source,
          campaign_tag: f.campaignTag,
          profile_id: f.profileId,
        });
        return JSON.stringify(r, null, 2);
      }
      case "ioc_import_misp": {
        const f = parseIocStringFields(args);
        const j = f.json;
        if (!j || !j.trim()) {
          return JSON.stringify({
            error: "Pass **json** (MISP Event export JSON as a string).",
          });
        }
        const r = await invoke<unknown>("ioc_import_misp", {
          json: j,
          source: f.source,
          campaign_tag: f.campaignTag,
          profile_id: f.profileId,
        });
        return JSON.stringify(r, null, 2);
      }
      case "ioc_export_stix": {
        const s = parseIocSearchArgs(args);
        const pl = pickOptString(args, [
          "producer_label",
          "producerLabel",
          "label",
          "producer",
          "name",
        ]);
        const j = await invoke<string>("ioc_export_stix", {
          value_contains: s.valueContains,
          ioc_type: s.iocType,
          campaign: s.campaign,
          source: s.source,
          profile_id: s.profileId,
          all_profiles: s.allProfiles,
          include_false_positives: s.includeFalsePositives,
          limit: s.limit,
          producer_label: pl,
        });
        return j;
      }
      case "ioc_maintenance": {
        const r = await invoke<Record<string, number>>("ioc_maintenance");
        return JSON.stringify(r, null, 2);
      }
      case "api_request": {
        const url = String(args.url ?? args.endpoint ?? "").trim();
        const apiName = String(
          args.api_name ?? args.apiName ?? "",
        ).trim();
        if (!url || !apiName) {
          return JSON.stringify({ error: "api_request needs **url** and **api_name**." });
        }
        const r = await invoke<unknown>("api_request", {
          url,
          method: String(args.method ?? "GET"),
          headers: args.headers,
          body: typeof args.body === "string" ? args.body : undefined,
          api_name: apiName,
        });
        return JSON.stringify(r, null, 2);
      }
      case "enrich_ioc": {
        const f = parseIocStringFields(args);
        const ioc = f.value ?? (args.ioc as string | undefined);
        const iocType = f.iocType ?? (args.ioc_type as string | undefined);
        if (!ioc || !iocType) {
          return JSON.stringify({ error: "enrich_ioc needs **ioc** and **ioc_type**." });
        }
        const r = await invoke<unknown>("enrich_ioc", {
          ioc: String(ioc).trim(),
          ioc_type: String(iocType).trim(),
          profile_id: f.profileId,
        });
        return JSON.stringify(r, null, 2);
      }
      case "enrich_virustotal":
      case "enrich_shodan":
      case "enrich_abusech":
      case "enrich_otx": {
        const f = parseIocStringFields(args);
        const ioc = f.value ?? (args.ioc as string | undefined);
        const iocType = f.iocType ?? (args.ioc_type as string | undefined);
        if (!ioc || !iocType) {
          return JSON.stringify({ error: `${name} needs **ioc** and **ioc_type**.` });
        }
        const r = await invoke<unknown>(name, {
          ioc: String(ioc).trim(),
          ioc_type: String(iocType).trim(),
          profile_id: f.profileId,
        });
        return JSON.stringify(r, null, 2);
      }
      case "add_feed": {
        const r = await invoke<unknown>("add_feed", {
          name: String(args.name ?? ""),
          ftype: String(args.ftype ?? args.type ?? ""),
          url: args.url,
          api_key_ref: args.api_key_ref ?? args.apiKeyRef,
          poll_interval_minutes: parseOptInt(args.poll_interval_minutes),
          filter_tags: args.filter_tags ?? args.filterTags,
        });
        return JSON.stringify(r, null, 2);
      }
      case "list_feeds": {
        const r = await invoke<unknown>("list_feeds");
        return JSON.stringify(r, null, 2);
      }
      case "get_feed_status": {
        const id = String(args.id ?? args.feed_id ?? "").trim();
        if (!id) return JSON.stringify({ error: "get_feed_status needs **id**." });
        const r = await invoke<unknown>("get_feed_status", { id });
        return JSON.stringify(r, null, 2);
      }
      case "poll_feed": {
        const id = String(args.feed_id ?? args.id ?? "").trim();
        if (!id) return JSON.stringify({ error: "poll_feed needs **feed_id**." });
        const r = await invoke<unknown>("poll_feed", { feed_id: id });
        return JSON.stringify(r, null, 2);
      }
      case "feed_search": {
        const r = await invoke<unknown>("feed_search", {
          source: String(args.source ?? ""),
          value_contains: args.value_contains ?? args.valueContains,
          limit: parseOptInt(args.limit),
        });
        return JSON.stringify(r, null, 2);
      }
      case "feed_stats": {
        const r = await invoke<unknown>("feed_stats");
        return JSON.stringify(r, null, 2);
      }
      case "feed_health": {
        const r = await invoke<unknown>("feed_health");
        return JSON.stringify(r, null, 2);
      }
      case "source_reputation": {
        const r = await invoke<unknown>("source_reputation");
        return JSON.stringify(r, null, 2);
      }
      case "add_ioc_relationship": {
        const r = await invoke<unknown>("add_ioc_relationship", {
          source_ioc: String(args.source_ioc ?? args.sourceIoc ?? ""),
          target_ioc: String(args.target_ioc ?? args.targetIoc ?? ""),
          relationship_type: String(args.relationship_type ?? args.relationshipType ?? ""),
          source_data: args.source_data ?? args.sourceData,
          confidence: parseOptInt(args.confidence),
        });
        return JSON.stringify(r, null, 2);
      }
      case "ioc_pivot": {
        const r = await invoke<unknown>("ioc_pivot", {
          ioc_id: String(args.ioc_id ?? args.iocId ?? ""),
          relationship_type: args.relationship_type ?? args.relationshipType,
          limit: parseOptInt(args.limit),
        });
        return JSON.stringify(r, null, 2);
      }
      case "find_path": {
        const r = await invoke<unknown>("find_path", {
          from_ioc: String(args.from_ioc ?? args.fromIoc ?? ""),
          to_ioc: String(args.to_ioc ?? args.toIoc ?? ""),
          max_depth: parseOptI64Num(args, ["max_depth", "maxDepth"]),
        });
        return JSON.stringify(r, null, 2);
      }
      case "suggest_pivots": {
        const r = await invoke<unknown>("suggest_pivots", {
          ioc_id: String(args.ioc_id ?? args.iocId ?? ""),
          limit: parseOptInt(args.limit),
        });
        return JSON.stringify(r, null, 2);
      }
      case "campaign_analysis": {
        const r = await invoke<unknown>("campaign_analysis", {
          campaign_tag: String(args.campaign_tag ?? args.campaignTag ?? ""),
        });
        return JSON.stringify(r, null, 2);
      }
      case "record_sighting": {
        const r = await invoke<unknown>("record_sighting", {
          ioc_id: String(args.ioc_id ?? args.iocId ?? ""),
          source: args.source,
          context: args.context,
        });
        return JSON.stringify(r, null, 2);
      }
      case "ioc_timeline": {
        const r = await invoke<unknown>("ioc_timeline", {
          ioc_id: String(args.ioc_id ?? args.iocId ?? ""),
        });
        return JSON.stringify(r, null, 2);
      }
      case "campaign_track": {
        const r = await invoke<unknown>("campaign_track", {
          campaign_name: String(args.campaign_name ?? args.campaignName ?? ""),
          recent_days: parseOptI64Num(args, ["recent_days", "recentDays"]),
        });
        return JSON.stringify(r, null, 2);
      }
      case "emerging_threats": {
        const r = await invoke<unknown>("emerging_threats", {
          days: parseOptI64Num(args, ["days"]),
        });
        return JSON.stringify(r, null, 2);
      }
      case "campaign_compare": {
        const r = await invoke<unknown>("campaign_compare", {
          campaign_a: String(args.campaign_a ?? args.campaignA ?? ""),
          campaign_b: String(args.campaign_b ?? args.campaignB ?? ""),
        });
        return JSON.stringify(r, null, 2);
      }
      default: {
        const tools = getOllamaTools() as {
          type?: string;
          function?: { name?: string };
        }[];
        const names = tools
          .filter((t) => t.type === "function" && t.function?.name)
          .map((t) => t.function!.name as string);
        const sample = names.join(", ");
        return JSON.stringify({
          error: `Unknown tool: ${name}. The host only exposes: ${sample}. (There is no container.exec / docker.exec tool — use run_trusted_workflow, send_integrated_terminal, or run_command with paths under workspaceRoot from get_environment.)`,
        });
      }
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    agentWarn("dispatchTool error", name, msg);
    let errOut = msg;
    if (
      (name === "run_command" || name === "run") &&
      /pip/i.test(resolveRunCommandProgramAndArgv(args)?.program ?? "")
    ) {
      errOut = `${msg} For Python installs, prefer **program** \`python3\` and **args** \`["-m","pip","install",...]\` (or add \`pip3\`/\`pip\` to allowed executables in Settings).`;
    }
    return JSON.stringify({ error: errOut });
  }
}

const MAX_AGENT_STEPS = 32;

export type RunAgenticTurnOptions = {
  /** When aborted, the loop stops and may append placeholder tool results so the thread stays tool-call–valid. */
  signal?: AbortSignal;
};

/**
 * Runs Ollama chat with tools until the model returns no tool calls or limits hit.
 * Returns updated transcript (including new assistant + tool messages).
 */
export async function runAgenticTurn(
  transcript: OllamaMessage[],
  options?: RunAgenticTurnOptions,
): Promise<{ transcript: OllamaMessage[]; error?: string }> {
  const { signal } = options ?? {};
  const tools = getOllamaTools();
  let current = [...transcript];
  let steps = 0;
  let preFlight: Awaited<ReturnType<typeof preFlightCheck>>;
  try {
    preFlight = await preFlightCheck();
  } catch (e) {
    agentWarn("preFlightCheck failed", e);
    preFlight = {
      stale: false,
      warningLine: undefined,
      freshnessSummary: "",
    };
  }

  agentLog("runAgenticTurn start", {
    transcriptMessages: current.length,
    tools: tools.length,
    localIntelligenceStale: preFlight.stale,
  });

  while (steps++ < MAX_AGENT_STEPS) {
    if (signal?.aborted) {
      return { transcript: current, error: "Run cancelled by user." };
    }
    let res: Record<string, unknown>;
    try {
      res = await invoke<Record<string, unknown>>("ollama_chat", {
        messages: current.map(messageForApi),
        tools,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      agentWarn("ollama_chat invoke failed", msg);
      return { transcript: current, error: msg };
    }

    const resMessage = res.message as Record<string, unknown> | undefined;
    agentLog("ollama response step", steps, {
      hasMessage: Boolean(resMessage),
      model: typeof res.model === "string" ? res.model : undefined,
      done: res.done,
      topLevelKeys: Object.keys(res),
    });

    if (signal?.aborted) {
      return { transcript: current, error: "Run cancelled by user." };
    }

    const assistant = extractAssistantMessage(res);
    const calls = assistant.tool_calls;
    agentLog("assistant extracted", {
      contentLength: assistant.content?.length ?? 0,
      toolCallCount: calls?.length ?? 0,
      toolNames: summarizeOllamaToolCalls(calls),
    });
    current.push(assistant);

    if (!calls?.length) {
      agentWarn(
        "runAgenticTurn: stopping — no tool_calls (model finished or returned only text). If you expected tools, check Ollama model supports function calling.",
      );
      break;
    }

    for (let i = 0; i < calls.length; i++) {
      const tc = calls[i];
      if (signal?.aborted) {
        for (let j = i; j < calls.length; j++) {
          const t = calls[j];
          const n = t.function?.name ?? "";
          current.push(toolMsgCancelled(n, t));
        }
        return { transcript: current, error: "Run cancelled by user." };
      }
      let name = tc.function?.name ?? "";
      let args = parseToolArguments(tc.function?.arguments as unknown);
      const fixedName = canonicalizeHallucinatedToolName(name, args);
      if (fixedName !== name) {
        agentLog("dispatchTool: canonicalized tool name", name, "→", fixedName);
        name = fixedName;
      }
      const repaired = tryRepairRunToolToTerminal(name, args);
      if (repaired) {
        agentLog("repaired hallucinated tool", name, "→ send_integrated_terminal");
        name = repaired.function.name;
        args = parseToolArguments(repaired.function?.arguments as unknown);
      }
      const lastUser = getLastUserMessageText(current);
      let content: string;
      if (
        name === "run_trusted_workflow" &&
        lastUser &&
        isWorkflowCatalogQuestion(lastUser)
      ) {
        agentWarn(
          "run_trusted_workflow blocked: workflow catalog / list intent",
          lastUser.slice(0, 120),
        );
        content = JSON.stringify({
          error: "blocked_workflow_catalog_intent",
          message:
            "This user turn is a **list / catalog** question (what workflows or projects exist). The host does **not** run **run_trusted_workflow** here—starting a workflow would launch the runner, not print a catalog. Answer in prose: (1) **run_trusted_workflow** **workflow** values include `intelx`, `cve`/`cve_nvd`, and the CTI venv ids in `cti_workflows.json` (e.g. `ransomware`, `asm_fetch`, `social_mediav2`, …) mapping to monorepo folders; (2) list **top-level project folders** from the Session workspace index (or **analyze_workspace_run_requirements**); (3) optionally **read_text_file** `CTI_FUNCTION_MAP.md` / `SCRIPT_WORKFLOWS.md` when they exist. Keep the reply short.",
        });
      } else {
        content = await dispatchTool(name, args, signal);
      }
      const toolMsg: OllamaMessage = {
        role: "tool",
        content,
        tool_name: name,
        name,
        tool_call_id: tc.id,
      };
      current.push(toolMsg);
      if (signal?.aborted) {
        for (let j = i + 1; j < calls.length; j++) {
          const t = calls[j];
          const n2 = t.function?.name ?? "";
          current.push(toolMsgCancelled(n2, t));
        }
        return { transcript: current, error: "Run cancelled by user." };
      }
    }
  }

  if (steps >= MAX_AGENT_STEPS) {
    prependStaleWarningToLastAssistant(current, preFlight.warningLine);
    return {
      transcript: current,
      error: "Stopped: maximum agent steps reached.",
    };
  }

  prependStaleWarningToLastAssistant(current, preFlight.warningLine);
  return { transcript: current };
}
