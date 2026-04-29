import { invoke } from "@tauri-apps/api/core";
import type { OllamaMessage } from "./types";
import { agentLog, agentWarn } from "./agentDebug";
import { toolCallsToSummaryLines } from "../chatDisplay";

export type TaskVerifierVerdict = "satisfied" | "partial" | "not_satisfied" | "unclear";

export type TaskVerifierResult = {
  verdict: TaskVerifierVerdict;
  confidence: number;
  summary: string;
  gaps: string[];
  /** When the model did not return valid JSON */
  parseWarning?: string;
};

const VERIFIER_SYSTEM = `You are a **separate reviewer** (not the agent that did the work). Decide if the main agent’s last turn **fulfilled the user’s request** using the **user’s words** and the transcript.

**Rules**
- **Match the stack to the request (critical):** Infer what “run” means from the **user message**, not from a generic template. Examples for an All_Scripts-style workspace:
  - **“run cve” / CVE / NVD project** → usually **\`CVE_Project_NVD\`** with **\`python3\` / \`pip\`** per README—**do not** demand **Docker** or \`docker compose\` unless the user asked for Docker/containers **or** the README tool invocations clearly require it.
  - **“run intelx”** → may use **Docker** under \`Intelx_Crawler\`; that is **not** the same as “run cve”.
  - Never fault the agent for “missing Docker” when the user did not ask for Docker and the intended project is Python-first.
- You cannot see the user’s screen. **send_integrated_terminal** only confirms bytes were sent—you **cannot** know exit status; still, it **counts as an execution attempt** (not “no run happened”).
- If the transcript’s **tool-name list** or **## tool: send_integrated_terminal** / **## tool: run_trusted_workflow** / **## tool: run_command** / **## tool: run** sections appear, the agent **did** invoke the terminal or a captured command—**do not** claim “no execution” or “only planning” unless those tools are **absent** from the trace.
- **Assistant-only JSON is not execution:** If the assistant printed \`{"action":"…","params":{…}}\` or similar in **prose** but the **tool-name list** is still \`(none)\` or has no terminal/\`run\` tools, that is **not** a run—use **not_satisfied** for a **run / execute** request.
- For a **run / execute** request: **not_satisfied** because “nothing ran” requires **neither** \`send_integrated_terminal\` **nor** \`run_trusted_workflow\` **nor** \`run_command\` / \`run\` in the trace. If both \`read_text_file\` and \`send_integrated_terminal\` (or \`run_trusted_workflow\` / \`run_command\` / \`run\`) appear, prefer **partial** (deps/menu may still be needed) or **satisfied** if the user only asked to start the app—**not** **not_satisfied** solely due to missing log output in chat.
- If the assistant **claims** success without any matching tools, use **not_satisfied** or **partial** and list **gaps**.

**Output (mandatory):** The host uses JSON mode. Your entire reply must be **one JSON object only**—no markdown, no preamble, no "Analysis" headings, no text outside the object. Use exactly these keys:
{"verdict":"satisfied"|"partial"|"not_satisfied"|"unclear","confidence":0.85,"summary":"2-3 sentences","gaps":["gap1","gap2"]}
Use an empty array for gaps when none: "gaps":[]`;

const MAX_ASSISTANT_CONTENT = 3_500;
const MAX_TOOL_BODY = 8_000;
const MAX_TRACE = 36_000;

/**
 * Compact the new messages from one user send (assistant + tool loop) for the verifier model.
 * Tool names and **tool results come first** so long chain-of-thought does not get truncated
 * away from the verifier (fixes false "no send_integrated_terminal" verdicts).
 */
export function formatAgentTurnForVerifier(messages: OllamaMessage[]): string {
  const toolNamesOrdered: string[] = [];
  const toolBlocks: string[] = [];
  const assistantBlocks: string[] = [];

  for (const m of messages) {
    if (m.role === "assistant" && m.tool_calls?.length) {
      for (const tc of m.tool_calls) {
        const n = tc.function?.name?.trim();
        if (n) toolNamesOrdered.push(n);
      }
    }
  }

  for (const m of messages) {
    if (m.role === "tool") {
      const name = m.tool_name ?? m.name ?? "tool";
      const raw = m.content ?? "";
      const body =
        raw.length > MAX_TOOL_BODY
          ? `${raw.slice(0, MAX_TOOL_BODY)}\n[tool result truncated]`
          : raw;
      toolBlocks.push(`## tool: ${name}\n${body}\n`);
    }
  }

  for (const m of messages) {
    if (m.role === "assistant") {
      let s = "## assistant\n";
      const c = m.content?.trim() ?? "";
      if (c) {
        s +=
          c.length > MAX_ASSISTANT_CONTENT
            ? `${c.slice(0, MAX_ASSISTANT_CONTENT)}\n[assistant content truncated]\n`
            : `${c}\n`;
      }
      if (m.tool_calls?.length) {
        s += "Tool calls (planned):\n";
        for (const { line } of toolCallsToSummaryLines(m.tool_calls)) {
          s += `- ${line}\n`;
        }
      }
      if (m.thinking?.trim()) {
        const t = m.thinking.trim();
        s += `Chain-of-thought (truncated): ${t.slice(0, 1_500)}${t.length > 1_500 ? "…" : ""}\n`;
      }
      assistantBlocks.push(s);
    }
  }

  const unique = [...new Set(toolNamesOrdered)];
  const header = `### Tool names invoked this turn (in order)\n${unique.length ? unique.join(" → ") : "(none)"}\n\n`;
  const out = header + toolBlocks.join("\n") + assistantBlocks.join("\n");
  if (out.length > MAX_TRACE) {
    return `${out.slice(0, MAX_TRACE)}\n\n[trace truncated for verifier — tool section was placed first; if unsure, check tool names above]`;
  }
  return out;
}

const EXECUTION_TOOL_NAMES = new Set([
  "send_integrated_terminal",
  "run_command",
  "run",
  "run_trusted_workflow",
]);

function hadExecutionTool(messages: OllamaMessage[]): boolean {
  for (const m of messages) {
    if (m.role === "tool") {
      const n = (m.tool_name ?? m.name ?? "").trim().toLowerCase();
      if (n && EXECUTION_TOOL_NAMES.has(n)) return true;
    }
    if (m.role === "assistant" && m.tool_calls?.length) {
      for (const tc of m.tool_calls) {
        const n = tc.function?.name?.trim().toLowerCase() ?? "";
        if (n && EXECUTION_TOOL_NAMES.has(n)) return true;
      }
    }
  }
  return false;
}

/** True when the user likely wanted an actual command/terminal run (not a conceptual “how it runs” question). */
function userRequestedCommandExecution(userRequest: string): boolean {
  const u = userRequest.trim();
  if (!u) return false;
  if (/^(?:how|what|why|when|where|explain|describe|tell me|should i|can you explain)\b/i.test(u)) {
    return false;
  }
  if (/\bhow (?:do |to )?(?:i |we )?(?:run|execute|start|launch)\b/i.test(u.toLowerCase())) {
    return false;
  }
  return /\b(?:run|execute|start|launch)\b/i.test(u);
}

function guardSatisfiedRunWithoutExecution(
  userRequest: string,
  messages: OllamaMessage[],
  r: TaskVerifierResult,
): TaskVerifierResult {
  if (r.verdict !== "satisfied") return r;
  if (hadExecutionTool(messages)) return r;
  if (!userRequestedCommandExecution(userRequest)) return r;
  const gap =
    "Transcript has no send_integrated_terminal, run_trusted_workflow, run_command, or run tool call; text or JSON in the assistant message does not count as execution.";
  return {
    ...r,
    verdict: "not_satisfied",
    confidence: Math.min(r.confidence, 0.75),
    gaps: r.gaps.includes(gap) ? r.gaps : [...r.gaps, gap],
  };
}

function extractMessageText(res: Record<string, unknown>): string {
  const message = res.message as Record<string, unknown> | undefined;
  if (!message || typeof message !== "object") {
    return typeof res === "string" ? res : JSON.stringify(res);
  }
  let content = typeof message.content === "string" ? message.content : "";
  const thinking = message.thinking;
  if ((!content || !String(content).trim()) && typeof thinking === "string" && thinking.trim()) {
    content = thinking;
  }
  return content;
}

/** Extract one balanced `{...}` from **startChar**, respecting strings and escapes. */
function extractBalancedObject(text: string, startChar: number): string | null {
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let j = startChar; j < text.length; j++) {
    const ch = text[j];
    if (inStr) {
      if (esc) {
        esc = false;
      } else if (ch === "\\") {
        esc = true;
      } else if (ch === '"') {
        inStr = false;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
      continue;
    }
    if (ch === "{") depth++;
    if (ch === "}") {
      depth--;
      if (depth === 0) {
        return text.slice(startChar, j + 1);
      }
    }
  }
  return null;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  const t = text.trim();
  const direct = tryParseObject(t);
  if (direct) return direct;
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    const inFence = tryParseObject(fence[1].trim());
    if (inFence) return inFence;
  }
  const i = t.indexOf("{");
  if (i >= 0) {
    const balanced = extractBalancedObject(t, i);
    if (balanced) {
      const fromBalanced = tryParseObject(balanced);
      if (fromBalanced) return fromBalanced;
    }
    const j = t.lastIndexOf("}");
    if (j > i) {
      const fromSlice = tryParseObject(t.slice(i, j + 1));
      if (fromSlice) return fromSlice;
    }
  }
  return null;
}

/** When the model ignores JSON mode, infer a best-effort verdict from English text. */
function inferVerdictFromProse(text: string): TaskVerifierResult {
  const t = text.replace(/\s+/g, " ").trim();
  const summary = t.length > 900 ? `${t.slice(0, 897)}…` : t;
  const lower = t.toLowerCase();

  const explicitVerdict = t.match(
    /(?:^|[\s"'{,])verdict["']?\s*[:=]\s*["']?(satisfied|partial|not_satisfied|unclear)\b/i,
  );
  if (explicitVerdict) {
    const v = explicitVerdict[1].toLowerCase() as TaskVerifierVerdict;
    if (v === "satisfied" || v === "partial" || v === "not_satisfied" || v === "unclear") {
      return {
        verdict: v,
        confidence: 0.55,
        summary: summary || "No review text.",
        gaps: [
          "Verifier returned prose; matched an explicit verdict word (heuristic). Prefer a JSON-only verifier model.",
        ],
        parseWarning: "prose_fallback",
      };
    }
  }

  /** Verifier is summarizing a trace: these mean the main agent *did* try to execute something. */
  const describedExecution =
    /\bsend_integrated_terminal\b|##\s*tool:\s*send_integrated|integrated\s+terminal|docker\s+compose|intelx-scraper|\brun_command\b|##\s*tool:\s*run_command|\b`run`\b|##\s*tool:\s*run\b/i.test(
      t,
    );
  const describedOnlyReadNoRun =
    /\bonly\s+(read|read_text_file)\b|no\s+send_integrated|neither\s+.*run_command|neither.*send_integrated/i.test(
      lower,
    ) &&
    !describedExecution;

  let verdict: TaskVerifierVerdict = "unclear";
  let confidence = 0.45;

  if (
    !describedExecution &&
    (/\bnot_?satisfied\b|not\s+fully\s+satisfied|did\s+not\s+run|no\s+(?:tool\s+)?invocation|only\s+planning\b/i.test(
      lower,
    ) ||
      describedOnlyReadNoRun)
  ) {
    verdict = "not_satisfied";
  } else if (describedExecution) {
    /** Do not use the old "missing … send_integrated" pattern — it false-triggered on long mixed prose. */
    verdict = "partial";
    confidence = 0.55;
    if (/\bsatisfi(?:ed|es)\b|successfully\s+run|fulfilled|adequate/i.test(lower)) {
      verdict = "satisfied";
      confidence = 0.5;
    } else if (/\bread_text_file.*(fail|error|not exist|no such file)|path\s+didn(?:'t| not) exist|wrong\s+path/i.test(t)) {
      /* README miss + terminal attempt = common partial outcome */
      verdict = "partial";
      confidence = 0.5;
    }
  } else if (/\bpartial(ly)?\b|incomplete|not\s+yet\s+run|should\s+next|needs?\s+to\s+execute/i.test(lower)) {
    verdict = "partial";
  } else if (/\bsatisf(y|ied|ies)\b|fulfilled|completed successfully|task\s+is\s+complete/i.test(lower)) {
    verdict = "satisfied";
  }

  return {
    verdict,
    confidence,
    summary: summary || "No review text.",
    gaps: [
      "Verifier returned prose instead of JSON; this verdict is a host heuristic. Use Ollama JSON format or a small instruction model for strict structured reviews.",
    ],
    parseWarning: "prose_fallback",
  };
}

function tryParseObject(s: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(s) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function coerceVerdict(v: unknown): TaskVerifierVerdict {
  if (v === "satisfied" || v === "partial" || v === "not_satisfied" || v === "unclear") {
    return v;
  }
  return "unclear";
}

function toTaskVerifierResult(o: Record<string, unknown>): TaskVerifierResult {
  const confRaw = o.confidence;
  let confidence = typeof confRaw === "number" && !Number.isNaN(confRaw) ? confRaw : 0.5;
  if (confidence > 1) confidence = 1;
  if (confidence < 0) confidence = 0;
  const summary =
    typeof o.summary === "string" && o.summary.trim()
      ? o.summary.trim()
      : "No summary in verifier JSON.";

  let gaps: string[] = [];
  if (Array.isArray(o.gaps)) {
    gaps = o.gaps
      .map((x) => (typeof x === "string" ? x : JSON.stringify(x)))
      .filter(Boolean);
  }

  return {
    verdict: coerceVerdict(o.verdict),
    confidence,
    summary,
    gaps,
  };
}

/**
 * Second Ollama pass: no tools, JSON-oriented system prompt. Compares the user request to
 * the assistant+tool messages from the last **runAgenticTurn** only.
 */
export async function runTaskVerifier(
  userRequest: string,
  agentTurnMessages: OllamaMessage[],
): Promise<TaskVerifierResult> {
  const trace = formatAgentTurnForVerifier(agentTurnMessages);
  const userPayload = `## User request (judge **this** phrasing—do not require Docker unless they asked for Docker / containers; “run cve” is not “run docker”)\n${userRequest}\n\n## Transcript: this turn only (assistant + tool results)\n${trace}`;

  agentLog("runTaskVerifier: trace chars", userPayload.length);

  const res = await invoke<Record<string, unknown>>("ollama_verifier_chat", {
    messages: [
      { role: "system", content: VERIFIER_SYSTEM },
      { role: "user", content: userPayload },
    ],
  });

  const text = extractMessageText(res);
  if (!text.trim()) {
    agentWarn("runTaskVerifier: empty model text");
    return {
      verdict: "unclear",
      confidence: 0,
      summary: "The verifier model returned no text.",
      gaps: ["Could not obtain a review."],
      parseWarning: "empty",
    };
  }

  const parsed = parseJsonObject(text);
  if (parsed) {
    return guardSatisfiedRunWithoutExecution(
      userRequest,
      agentTurnMessages,
      toTaskVerifierResult(parsed),
    );
  }

  agentWarn("runTaskVerifier: could not parse JSON, prose fallback, raw length", text.length);
  const fallback = inferVerdictFromProse(text);
  return guardSatisfiedRunWithoutExecution(userRequest, agentTurnMessages, {
    ...fallback,
    summary:
      fallback.summary.length >= 500
        ? fallback.summary
        : `${fallback.summary}\n\n(Verifier raw start: ${text.slice(0, 280)}${text.length > 280 ? "…" : ""})`,
  });
}
