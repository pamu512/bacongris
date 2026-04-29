import type { OllamaMessage } from "./agent/types";
import {
  coerceCwdArg,
  coerceProgramArg,
  parseToolArguments,
} from "./agent/toolArgs";

export type RunCommandDenied = {
  program: string;
  args: string[];
  cwd: string | null;
  requested: string;
  reason: string;
  suggestedPath: string | null;
  toolMessageIndex: number;
};

function getArgsArray(args: Record<string, unknown>): string[] {
  const raw = args.args ?? args.argv;
  if (!Array.isArray(raw)) return [];
  return raw.map((a) => String(a));
}

/**
 * If the last `run_command` tool result is a denial, return the matching assistant call + metadata
 * so the UI can offer “allow once” / “add to allowlist” / retry.
 */
export function findRunCommandDenial(
  msgs: OllamaMessage[],
): RunCommandDenied | null {
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role !== "tool" || m.content == null || m.content === "") continue;
    let parsed: {
      denied?: {
        requested: string;
        reason: string;
        suggestedPath?: string;
      };
    };
    try {
      parsed = JSON.parse(m.content) as typeof parsed;
    } catch {
      continue;
    }
    if (!parsed.denied) continue;

    for (let j = i - 1; j >= 0; j--) {
      const a = msgs[j];
      if (a.role !== "assistant" || !a.tool_calls?.length) continue;
      const tc = a.tool_calls.find((t) => t.function?.name === "run_command");
      if (!tc) continue;
      const args = parseToolArguments(tc.function?.arguments);
      return {
        program: coerceProgramArg(args),
        args: getArgsArray(args),
        cwd: coerceCwdArg(args),
        requested: parsed.denied.requested,
        reason: parsed.denied.reason,
        suggestedPath: parsed.denied.suggestedPath ?? null,
        toolMessageIndex: i,
      };
    }
    return null;
  }
  return null;
}
