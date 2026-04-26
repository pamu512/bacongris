import { invoke } from "@tauri-apps/api/core";
import type { OllamaMessage, OllamaToolCall } from "./types";
import { getOllamaTools } from "./tools";
import {
  coerceCwdArg,
  coercePathArg,
  coerceProgramArg,
  coerceTerminalDataArg,
  parseAnalyzeWorkspaceCallArgs,
  parseToolArguments,
} from "./toolArgs";

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

async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
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
        const result = await invoke<unknown>("run_command", {
          program,
          args: argv,
          cwd,
        });
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
      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return JSON.stringify({ error: msg });
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

  while (steps++ < MAX_AGENT_STEPS) {
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

    const assistant = extractAssistantMessage(res);
    current.push(assistant);

    const calls = assistant.tool_calls;
    if (!calls?.length) {
      break;
    }

    for (const tc of calls) {
      const name = tc.function?.name ?? "";
      const args = parseToolArguments(tc.function?.arguments as unknown);
      const content = await dispatchTool(name, args);
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
