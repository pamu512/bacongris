import { invoke } from "@tauri-apps/api/core";
import type { OllamaMessage, OllamaToolCall } from "./types";
import { getOllamaTools } from "./tools";
import {
  coerceCwdArg,
  coerceFileContentArg,
  coercePathArg,
  coerceProgramArg,
  coerceTerminalDataArg,
  parseAnalyzeWorkspaceCallArgs,
  parseIocSearchArgs,
  parseIocStringFields,
  parseToolArguments,
  pickOptString,
} from "./toolArgs";

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
function messageForApi(m: OllamaMessage): OllamaMessage {
  const { localId: _id, ...rest } = m;
  return rest;
}

function extractAssistantMessage(res: Record<string, unknown>): OllamaMessage {
  const message = res.message as Record<string, unknown> | undefined;
  if (!message || typeof message !== "object") {
    return { role: "assistant", content: JSON.stringify(res) };
  }
  const role = (message.role as string) || "assistant";
  const content =
    typeof message.content === "string" ? message.content : undefined;
  const tool_calls = message.tool_calls as OllamaToolCall[] | undefined;
  return { role: role as "assistant", content, tool_calls };
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
        const path = coercePathArg(args);
        if (!path) {
          return JSON.stringify({ error: "Missing path for list_directory." });
        }
        const rows = await invoke<unknown>("list_directory", { path });
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
      case "run_command": {
        const program = coerceProgramArg(args);
        if (!program) {
          return JSON.stringify({
            error:
              "Missing program. Use an allowed executable name (e.g. python3) or full path. For Docker Compose v2 prefer: program docker, args [\"compose\",\"-f\",composeFile,\"up\",...].",
          });
        }
        const rawArgs = args.args ?? args.argv ?? args.Arguments;
        const argv = Array.isArray(rawArgs)
          ? rawArgs.map((a) => String(a))
          : [];
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
      case "send_integrated_terminal": {
        const data = coerceTerminalDataArg(args);
        if (!data) {
          return JSON.stringify({
            error:
              "Missing text to send. Pass **text** (or **data**) with the characters to type; add \\n at the end to run a line.",
          });
        }
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
      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return JSON.stringify({ error: msg });
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
      return { transcript: current, error: msg };
    }

    if (signal?.aborted) {
      return { transcript: current, error: "Run cancelled by user." };
    }

    const assistant = extractAssistantMessage(res);
    current.push(assistant);

    const calls = assistant.tool_calls;
    if (!calls?.length) {
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
      const name = tc.function?.name ?? "";
      const args = parseToolArguments(tc.function?.arguments as unknown);
      const content = await dispatchTool(name, args, signal);
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
    return {
      transcript: current,
      error: "Stopped: maximum agent steps reached.",
    };
  }

  return { transcript: current };
}
