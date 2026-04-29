import { invoke } from "@tauri-apps/api/core";
import type { OllamaMessage, OllamaToolCall } from "./types";
import { getOllamaTools } from "./tools";
import { agentLog, agentWarn, summarizeOllamaToolCalls } from "./agentDebug";
import {
  tryExtractBashFictionSendTerminal,
  tryExtractToolCallsFromText,
  tryRepairRunToolToTerminal,
} from "./toolCallFallback";
import {
  coerceCwdArg,
  coercePathArg,
  coerceProgramArg,
  coerceTerminalDataArg,
  ensurePtyLineSubmitted,
  normalizeTerminalEscapeLiterals,
  preferPython3Command,
  parseAnalyzeWorkspaceCallArgs,
  getRunCommandArgv,
  parseToolArguments,
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
import { prepareForOllamaRequest } from "./ollamaMessages";
import { isWorkflowCatalogQuestion } from "./routingHints";

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

async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
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
        const text = await invoke<string>("read_text_file", { path });
        return text;
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
      case "run_trusted_workflow": {
        const workflow = coerceTrustedWorkflowArg(args);
        if (!workflow) {
          return JSON.stringify({
            error:
              "Missing workflow. Pass workflow: \"intelx\" | \"cve\" | \"cve_nvd\" (CVE_Project_NVD).",
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
        return JSON.stringify(result, null, 2);
      }
      case "run_command":
      case "run": {
        const program = coerceProgramArg(args);
        if (!program) {
          return JSON.stringify({
            error:
              "Missing program. Use an allowed executable name (e.g. python3) or full path. For Docker Compose v2 prefer: program docker, args [\"compose\",\"-f\",composeFile,\"up\",...].",
          });
        }
        const argv = getRunCommandArgv(args);
        const cwd = coerceCwdArg(args);
        const result = await invoke<unknown>("run_command", {
          program,
          args: argv,
          cwd,
        });
        return JSON.stringify(result, null, 2);
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
      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    agentWarn("dispatchTool error", name, msg);
    let errOut = msg;
    if ((name === "run_command" || name === "run") && /pip/i.test(coerceProgramArg(args) || "")) {
      errOut = `${msg} For Python installs, prefer **program** \`python3\` and **args** \`["-m","pip","install",...]\` (or add \`pip3\`/\`pip\` to allowed executables in Settings).`;
    }
    return JSON.stringify({ error: errOut });
  }
}

const MAX_AGENT_STEPS = 32;

/**
 * Runs Ollama chat with tools until the model returns no tool calls or limits hit.
 * Returns updated transcript (including new assistant + tool messages).
 */
export async function runAgenticTurn(
  transcript: OllamaMessage[],
): Promise<{ transcript: OllamaMessage[]; error?: string }> {
  const tools = getOllamaTools();
  let current = [...transcript];
  let steps = 0;

  agentLog("runAgenticTurn start", { transcriptMessages: current.length, tools: tools.length });

  while (steps++ < MAX_AGENT_STEPS) {
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

    for (const tc of calls) {
      let name = tc.function?.name ?? "";
      let args = parseToolArguments(tc.function?.arguments as unknown);
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
            "This user turn is a **list / catalog** question (what workflows or projects exist). The host does **not** run **run_trusted_workflow** here—starting **intelx** or **cve** would launch the runner/Docker, not print a catalog. Answer in prose: (1) **run_trusted_workflow** only accepts **workflow** `intelx` | `cve` | `cve_nvd` (CVE uses **CVE_Project_NVD**); (2) list other **top-level project folders** from the Session workspace index (or from **analyze_workspace_run_requirements** if the thread has no index yet); (3) optionally **read_text_file** `CTI_FUNCTION_MAP.md` / `SCRIPT_WORKFLOWS.md` when they exist. Keep the reply short—bullets, not a full venv guide for every folder unless the user asked for setup.",
        });
      } else {
        content = await dispatchTool(name, args);
      }
      const toolMsg: OllamaMessage = {
        role: "tool",
        content,
        tool_name: name,
        name,
        tool_call_id: tc.id,
      };
      current.push(toolMsg);
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
