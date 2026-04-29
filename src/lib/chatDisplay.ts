import type { OllamaMessage, OllamaToolCall } from "./agent/types";

/** One-line status for the Thinking bar (collapsed by default). */
export function workspaceIndexStatus(jsonStr: string | null, loading: boolean): string {
  if (loading) return "Building index…";
  if (!jsonStr) return "— send a message to index";
  try {
    const o = JSON.parse(jsonStr) as {
      workflowIndex?: unknown[];
      manifestFiles?: unknown[];
      workspaceRoot?: string;
    };
    const n = Array.isArray(o.workflowIndex) ? o.workflowIndex.length : 0;
    const m = Array.isArray(o.manifestFiles) ? o.manifestFiles.length : 0;
    if (n === 0 && m === 0) return "Index ready";
    const w = o.workspaceRoot ? ` · ${shortPath(o.workspaceRoot)}` : "";
    return `${n} project(s), ${m} manifest(s)${w}`;
  } catch {
    return "Index ready";
  }
}

function shortPath(p: string, max = 36): string {
  if (p.length <= max) return p;
  return `…${p.slice(-max + 1)}`;
}

export function workspaceIndexProjectNames(
  jsonStr: string | null,
  max = 14,
): string[] {
  if (!jsonStr) return [];
  try {
    const o = JSON.parse(jsonStr) as {
      workflowIndex?: { relativePath?: string }[];
    };
    const wf = o.workflowIndex ?? [];
    return wf
      .map((e) => e.relativePath)
      .filter((x): x is string => Boolean(x))
      .slice(0, max);
  } catch {
    return [];
  }
}

function parseCallArgs(
  args: string | Record<string, unknown> | undefined,
): string {
  if (args == null) return "";
  if (typeof args === "string") {
    try {
      const p = JSON.parse(args) as Record<string, unknown>;
      return formatArgsObject(p);
    } catch {
      return args.length > 160 ? `${args.slice(0, 157)}…` : args;
    }
  }
  return formatArgsObject(args);
}

function formatArgsObject(p: Record<string, unknown>): string {
  return Object.entries(p)
    .map(([k, v]) => {
      const s = typeof v === "string" ? v : JSON.stringify(v);
      const t = s.length > 100 ? `${s.slice(0, 97)}…` : s;
      return `${k}=${t}`;
    })
    .join(", ");
}

export function toolCallsToSummaryLines(
  calls: OllamaToolCall[] | undefined,
): { title: string; line: string }[] {
  if (!calls?.length) return [];
  return calls.map((tc) => {
    const name = tc.function?.name ?? "tool";
    const a = parseCallArgs(
      tc.function?.arguments as string | Record<string, unknown> | undefined,
    );
    return {
      title: name,
      line: a ? `${name} — ${a}` : name,
    };
  });
}

export function toolResultForDisplay(
  content: string | undefined,
): { headline: string; isError: boolean; raw: string } {
  const raw = content ?? "";
  if (!raw.trim()) {
    return { headline: "(empty)", isError: false, raw };
  }
  try {
    const j = JSON.parse(raw) as { error?: unknown; message?: string };
    if (j != null && typeof j === "object" && "error" in j && j.error != null) {
      const err = String(j.error);
      return { headline: err, isError: true, raw };
    }
  } catch {
    /* not JSON */
  }
  if (raw.length < 400) {
    return { headline: raw, isError: false, raw };
  }
  return {
    headline: `Output · ${(raw.length / 1024).toFixed(1)} KB (expand for full text)`,
    isError: false,
    raw,
  };
}

export type LastTurnThought = {
  /** e.g. "1.2" */
  durationLabel: string;
  /** One short sentence, Cursor-style. */
  headline: string;
  /** Shown on the closed row, e.g. "2 file reads · 1 list" */
  subline: string;
  /** Expand for bullets */
  detailLines: string[];
};

function extractPathFromArgs(
  args: string | Record<string, unknown> | undefined,
): string | null {
  if (args == null) return null;
  const obj =
    typeof args === "string"
      ? (() => {
          try {
            return JSON.parse(args) as Record<string, unknown>;
          } catch {
            return null;
          }
        })()
      : args;
  if (!obj || typeof obj !== "object") return null;
  if (typeof obj.path === "string") return obj.path;
  if (Array.isArray(obj.args) && obj.args.length)
    return String(obj.args[0]).slice(0, 80);
  return null;
}

/**
 * Build a Cursor-like "Thought" summary from the messages produced in the last agent turn
 * (assistant + tool). Ollama does not stream private chain-of-thought; this is all we can
 * show without a second model pass to paraphrase.
 */
export function summarizeAgentTurn(
  newMessages: OllamaMessage[],
  durationMs: number,
  options: { loadedWorkspaceIndex: boolean },
): LastTurnThought {
  const s = Math.max(0, durationMs / 1000).toFixed(1);
  const durationLabel = s;

  let readFile = 0;
  let listDir = 0;
  let analyze = 0;
  let runCmd = 0;
  let env = 0;
  let terminal = 0;
  let other = 0;
  const pathHints: string[] = [];

  for (const m of newMessages) {
    if (m.role !== "assistant" || !m.tool_calls) continue;
    for (const tc of m.tool_calls) {
      const n = tc.function?.name ?? "";
      const a = tc.function?.arguments;
      if (n === "read_text_file") {
        readFile++;
        const p = extractPathFromArgs(
          a as string | Record<string, unknown> | undefined,
        );
        if (p) pathHints.push(p);
      } else if (n === "list_directory") {
        listDir++;
        const p = extractPathFromArgs(
          a as string | Record<string, unknown> | undefined,
        );
        if (p) pathHints.push(`list: ${p}`);
      } else if (n === "analyze_workspace_run_requirements") {
        analyze++;
      } else if (n === "run_command" || n === "run") {
        runCmd++;
      } else if (n === "get_environment") {
        env++;
      } else if (n === "send_integrated_terminal" || n === "run_trusted_workflow") {
        terminal++;
      } else {
        other++;
        if (n) pathHints.push(`(tool ${n})`);
      }
    }
  }

  const toolCalls =
    readFile + listDir + analyze + runCmd + env + terminal + other;
  const explored = readFile + listDir;
  const scans = analyze;

  const bits: string[] = [];
  if (explored) bits.push(`${explored} path(s) explored`);
  if (scans) bits.push(`${scans} workspace scan${scans > 1 ? "s" : ""}`);
  if (runCmd) bits.push(`${runCmd} command${runCmd > 1 ? "s" : ""}`);
  if (env) bits.push(`${env} env`);
  if (terminal) bits.push(`${terminal} terminal`);
  if (other) bits.push(`${other} other`);
  if (toolCalls === 0 && !options.loadedWorkspaceIndex) {
    bits.push("no tools");
  }
  const subline =
    bits.length > 0
      ? bits.join(" · ")
      : options.loadedWorkspaceIndex
        ? "index only"
        : "no tool activity in stream";

  let headline = "Answered in one step.";
  if (options.loadedWorkspaceIndex && toolCalls > 0) {
    headline =
      "A workspace index was loaded, then the model used tools in a follow-up loop.";
  } else if (options.loadedWorkspaceIndex) {
    headline = "A fresh workspace index was built and sent with your message.";
  } else if (toolCalls > 0) {
    headline =
      "The model used tools in a multi-step loop (see detail for paths and any errors).";
  }

  const detailLines: string[] = [];
  if (pathHints.length) {
    detailLines.push("Paths & requests:");
    for (const p of pathHints.slice(0, 16)) {
      detailLines.push(`  · ${p}`);
    }
    if (pathHints.length > 16) {
      detailLines.push(`  · … ${pathHints.length - 16} more lines`);
    }
  }
  for (const m of newMessages) {
    if (m.role === "tool") {
      const name = m.tool_name ?? m.name ?? "tool";
      const r = toolResultForDisplay(m.content);
      if (r.isError) {
        const short = r.headline.length > 220 ? `${r.headline.slice(0, 220)}…` : r.headline;
        detailLines.push(`${name}: ${short}`);
      }
    }
  }

  return { durationLabel, headline, subline, detailLines };
}
