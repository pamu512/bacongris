import type { OllamaToolCall } from "./types";
import { getOllamaTools } from "./tools";
import { VISUAL_WORKSPACE_MAP } from "../visualWorkspaceMap";

let allowedNames: Set<string> | null = null;

function getAllowedToolNames(): Set<string> {
  if (allowedNames) return allowedNames;
  const tools = getOllamaTools() as {
    type?: string;
    function?: { name?: string };
  }[];
  allowedNames = new Set(
    tools
      .filter((t) => t.type === "function" && t.function?.name)
      .map((t) => t.function!.name as string),
  );
  return allowedNames;
}

/**
 * Some models prefix tools (`tool.get_environment`), use JSON-RPC `method`, or send channel noise
 * (`assistant<|channel|>…`). Map to a real Ollama tool name when possible.
 */
function pascalOrMixedToSnake(s: string): string {
  if (!s) return s;
  return s
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase();
}

/** Common wrong names from local models → real `function.name`. */
const TOOL_NAME_ALIASES: Record<string, string> = {
  analysis_workspace_run_requirements: "analyze_workspace_run_requirements",
  analyse_workspace_run_requirements: "analyze_workspace_run_requirements",
  analysis_workspace_run_requirement: "analyze_workspace_run_requirements",
};

export function canonicalizeHallucinatedToolName(
  name: string,
  args: Record<string, unknown>,
): string {
  const allowed = getAllowedToolNames();
  if (allowed.has(name)) return name;

  const m = args["method"];
  if (typeof m === "string" && allowed.has(m.trim())) {
    return m.trim();
  }
  const fromName = pickStringField(args, ["name", "toolName", "tool"]);
  if (
    fromName &&
    allowed.has(fromName) &&
    (name === "assistant" || /^assistant/i.test(name))
  ) {
    return fromName;
  }

  let n = name.trim();

  // `tool:analyze_*`, `TOOL:LIST_DIRECTORY`, `function.read_text_file`, etc.
  for (let i = 0; i < 6; i++) {
    const next = n.replace(/^(?:tool|function|mcp|functions)[:._-]+/i, "").trim();
    if (next === n) break;
    n = next;
  }

  // `assistant<|channel|>list_directory`, `assistant:`, role noise
  n = n.replace(/^assistant\s*:\s*/i, "").trim();
  n = n.replace(/^assistant\s*/i, "").trim();
  while (/^<\|[^|]+\|\>/.test(n)) {
    n = n.replace(/^<\|[^|]+\|\>\s*/i, "").trim();
  }

  const aliased = TOOL_NAME_ALIASES[n] ?? TOOL_NAME_ALIASES[n.toLowerCase()];
  if (aliased && allowed.has(aliased)) return aliased;

  // Model sent only a role label; infer from args when obvious.
  if (!n || /^:+$/.test(n)) {
    const p = pickStringField(args, ["path", "Path", "file", "filepath", "filePath"]);
    if (p && allowed.has("list_directory")) return "list_directory";
    const inp = pickStringField(args, ["input", "workflow", "workflow_relative_path"]);
    if (inp && allowed.has("analyze_workspace_run_requirements")) {
      return "analyze_workspace_run_requirements";
    }
  }

  n = n.replace(/^(?:tool|function|mcp|functions)\.+/i, "");
  n = n.replace(/^(?:tool|function|mcp|functions)_+/i, "");
  if (allowed.has(n)) return n;
  if (n.includes(".")) {
    const last = n.split(".").pop() || n;
    const snake = pascalOrMixedToSnake(last);
    if (allowed.has(snake)) return snake;
  }
  const snake = pascalOrMixedToSnake(n);
  if (allowed.has(snake)) return snake;
  for (const a of allowed) {
    if (a.toLowerCase() === n.toLowerCase()) return a;
  }
  for (const a of allowed) {
    if (a.toLowerCase() === snake.toLowerCase()) return a;
  }
  return name;
}

function stripCodeFences(s: string): string {
  let t = s.trim();
  if (t.startsWith("```")) {
    t = t.replace(/^```[\w.-]*\s*\n?/i, "");
    t = t.replace(/\n?```\s*$/i, "");
  }
  return t.trim();
}

/** Multiple `{"name":"run_command",...}` lines without a JSON array wrapper. */
function splitTopLevelJsonObjects(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        out.push(s.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return out;
}

/**
 * Some models emit `{"action":"send_integrated_terminal","params":{...}}` instead of OpenAI
 * `tool_calls` — nothing runs until we map it to a real tool name + arguments.
 */
/** Common wrong paths from models (spaces / backslashes) → real top-level folder names. */
function normalizeAllScriptsProjectPathInCommand(s: string): string {
  let t = s;
  // e.g. python3 "Social\ Media\ V2/main.py" (one backslash per space) after JSON.parse
  t = t.replace(/Social\\\s+Media\\\s+V2/gi, "Social_MediaV2");
  // e.g. raw "Social\\ Media\\ V2" in prose (double backslash in file)
  t = t.replace(/Social\\\\\s+Media\\\\\s+V2/gi, "Social_MediaV2");
  // plain spaces (no project folder has spaces; avoid breaking unrelated prose)
  t = t.replace(/Social\s+Media\s+V2/gi, "Social_MediaV2");
  return t;
}

/**
 * qwen3-vl and others emit `{ "action": "send_integrated_terminal", "command": "…" }` with **no**
 * `params` / `arguments` object — map to a real `send_integrated_terminal` call.
 */
function tryActionFlatCommandToolCalls(
  o: Record<string, unknown>,
  name: string,
  allowed: Set<string>,
): OllamaToolCall[] | null {
  if (name !== "send_integrated_terminal" || !allowed.has(name)) return null;
  const textRaw = pickStringField(o, [
    "text",
    "command",
    "cmd",
    "line",
    "shell",
  ]);
  if (!textRaw) return null;
  const textNorm = normalizeAllScriptsProjectPathInCommand(textRaw.trim());
  const text = textNorm.endsWith("\n") ? textNorm : `${textNorm}\n`;
  const args: Record<string, unknown> = { text };
  const cwd = pickStringField(o, [
    "cwd",
    "Cwd",
    "workingDirectory",
    "working_directory",
  ]);
  if (cwd && !isPlaceholderCwd(cwd)) {
    args.cwd = cwd;
  }
  return [
    {
      id: `call-actionflat-${Date.now()}`,
      function: { name, arguments: args },
    },
  ];
}

function isPlaceholderCwd(cwd: string): boolean {
  const l = cwd.toLowerCase();
  return (
    l.includes("/path/to") ||
    l.includes("path/to/cve") ||
    l.includes("<workspace") ||
    l === "/path/to/cve_project"
  );
}

function tryActionParamsToolCalls(parsed: unknown): OllamaToolCall[] | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const o = parsed as Record<string, unknown>;
  const action = o.action;
  if (typeof action !== "string" || !action.trim()) return null;
  const name = canonicalizeHallucinatedToolName(action.trim(), o);
  const allowed = getAllowedToolNames();
  if (!allowed.has(name)) return null;
  const params = o.params ?? o.arguments;
  if (params && typeof params === "object" && !Array.isArray(params)) {
    return [
      {
        id: `call-action-${Date.now()}`,
        function: { name, arguments: params as Record<string, unknown> },
      },
    ];
  }
  const flat = tryActionFlatCommandToolCalls(o, name, allowed);
  return flat;
}

/**
 * If the model prints a tool call as JSON in `content` (instead of using API `tool_calls`),
 * parse and return synthetic tool_calls so the agent loop can still run tools.
 */
export function tryExtractToolCallsFromText(
  content: string | undefined,
): OllamaToolCall[] | null {
  if (content == null) return null;
  const allowed = getAllowedToolNames();
  const raw0 = stripCodeFences(content);
  const lead = raw0.indexOf("{");
  if (lead < 0) return null;
  const raw = raw0.slice(lead);

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    const pieces = splitTopLevelJsonObjects(raw);
    if (pieces.length === 0) return null;
    const toCall = makeToCall(allowed);
    const out: OllamaToolCall[] = [];
    for (let i = 0; i < pieces.length; i++) {
      try {
        const p = JSON.parse(pieces[i]) as unknown;
        const ap = tryActionParamsToolCalls(p);
        if (ap) {
          for (const x of ap) out.push(x);
          continue;
        }
        const sh = tryShorthandTopLevelToolJson(p);
        if (sh) {
          for (const x of sh) out.push(x);
          continue;
        }
        const c = toCall(p, i);
        if (c) out.push(c);
      } catch {
        /* skip bad slice */
      }
    }
    return out.length > 0 ? out : null;
  }

  const actionFirst = tryActionParamsToolCalls(parsed);
  if (actionFirst) return actionFirst;

  const shorthand = tryShorthandTopLevelToolJson(parsed);
  if (shorthand) return shorthand;

  const toCall = makeToCall(allowed);

  if (Array.isArray(parsed)) {
    const out: OllamaToolCall[] = [];
    for (let i = 0; i < parsed.length; i++) {
      const c = toCall(parsed[i], i);
      if (c) out.push(c);
    }
    return out.length > 0 ? out : null;
  }

  const one = toCall(parsed, 0);
  return one ? [one] : null;
}

/**
 * qwen3-vl / others sometimes end with ```bash\nsend_integrated_terminal "cd ..."``` instead
 * of native tool_calls. Parse a single-quoted or double-quoted first argument and emit a
 * synthetic call so the agent loop can still type into the real terminal.
 */
export function tryExtractBashFictionSendTerminal(
  content: string | undefined,
): OllamaToolCall | null {
  if (content == null || !content.trim()) return null;
  const allowed = getAllowedToolNames();
  if (!allowed.has("send_integrated_terminal")) return null;

  const key = "send_integrated_terminal";
  const k = content.indexOf(key);
  if (k < 0) return null;

  // Do not match JSON string values: "send_integrated_terminal" in `{"function":"…"}`
  if (k > 0 && content[k - 1] === '"') {
    const after = k + key.length;
    if (after < content.length && content[after] === '"') {
      return null;
    }
  }
  // Do not match prose that merely mentions the tool name (e.g. backticks) without a shell-style arg
  if (k > 0 && /[`'A-Za-z0-9_$]/.test(content[k - 1])) {
    return null;
  }

  let p = k + key.length;
  while (p < content.length && /\s/.test(content[p])) p += 1;
  if (p >= content.length) return null;
  const open = content[p];
  if (open !== '"' && open !== "'" && open !== "`") return null;
  p += 1;
  const buf: string[] = [];
  for (; p < content.length; p += 1) {
    const c = content[p];
    if (c === "\\" && p + 1 < content.length) {
      buf.push(content[p + 1]);
      p += 1;
      continue;
    }
    if (c === open) {
      const textRaw = buf.join("").trim();
      if (!textRaw) return null;
      const fixed = normalizeAllScriptsProjectPathInCommand(textRaw);
      const text = fixed.endsWith("\n") ? fixed : `${fixed}\n`;
      return {
        id: `call-bashshim-${Date.now()}`,
        function: { name: "send_integrated_terminal", arguments: { text } },
      };
    }
    buf.push(c);
  }
  return null;
}

/** `run` is a real tool (alias of run_command); keep other fake shell names for repair → terminal. */
const HALLUCINATED_RUN_NAMES = new Set(["execute", "shell", "exec"]);

function pickStringField(
  rec: Record<string, unknown>,
  keys: string[],
): string {
  for (const k of keys) {
    const v = rec[k];
    if (typeof v === "string" && v.trim() !== "") return v.trim();
  }
  return "";
}

function shellQuoteArg(a: string): string {
  if (/[\s'"$`\\]/.test(a)) {
    return `"${a.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return a;
}

function lineFromProgramAndArgv(
  program: string,
  argv: unknown,
): string | null {
  const p = program.trim();
  if (!p) return null;
  if (!Array.isArray(argv) || argv.length === 0) {
    return p;
  }
  const parts = [p, ...argv.map((x) => String(x))];
  return parts.map(shellQuoteArg).join(" ");
}

/**
 * Models invent tools like `{ "name": "run", "arguments": { "command": "python3 main.py" } }`.
 * Map to **send_integrated_terminal** so the agent loop can type into the real shell.
 */
function hallucinatedRunToSendTerminal(
  args: unknown,
  top: Record<string, unknown>,
): OllamaToolCall | null {
  const allowed = getAllowedToolNames();
  if (!allowed.has("send_integrated_terminal")) return null;

  const rec =
    args && typeof args === "object" && !Array.isArray(args)
      ? (args as Record<string, unknown>)
      : null;
  const base = rec ?? top;
  let command = pickStringField(base, ["command", "cmd", "line", "text"]);
  if (!command && typeof top.command === "string") {
    command = top.command.trim();
  }
  if (!command) {
    const prog = pickStringField(base, [
      "program",
      "Program",
      "executable",
    ]);
    const argv = base.args ?? base.argv ?? base.Arguments ?? base["arguments"];
    if (prog) {
      const line = lineFromProgramAndArgv(
        prog,
        Array.isArray(argv) ? argv : [],
      );
      if (line) command = line;
    }
  }
  if (!command?.trim()) return null;

  let line = normalizeAllScriptsProjectPathInCommand(command.trim());
  const needsCveDir =
    /\bmain\.py\b/.test(line) || /\brequirements\.txt\b/.test(line);
  if (!/^\s*cd\s/i.test(line) && needsCveDir) {
    const firstToken = line.split(/\s+/)[0] ?? "";
    if (!firstToken.includes("/") && firstToken !== "cd") {
      line = `cd ${VISUAL_WORKSPACE_MAP.VULNS_CVE} && ${line}`;
    }
  }

  let cwd =
    pickStringField(base, [
      "cwd",
      "Cwd",
      "workingDirectory",
      "working_directory",
    ]) || (typeof top.cwd === "string" ? top.cwd.trim() : "");
  if (cwd && (isPlaceholderCwd(cwd) || cwd.toLowerCase() === "workspace_root")) {
    cwd = "";
  }
  const argsOut: Record<string, unknown> = { text: line };
  if (cwd) {
    argsOut.cwd = cwd;
  }

  return {
    id: `call-runalias-${Date.now()}`,
    function: { name: "send_integrated_terminal", arguments: argsOut },
  };
}

/** When the API returns a fake tool name like `run` in native `tool_calls`, rewrite before dispatch. */
export function tryRepairRunToolToTerminal(
  name: string,
  args: Record<string, unknown>,
): OllamaToolCall | null {
  /* `run` / `run_command`: models often send `{ command: "python …" }` instead of program+args. */
  if (name === "run_command" || name === "run") {
    const hasProgram =
      typeof args.program === "string" && args.program.trim() !== "";
    const cmd = pickStringField(args, ["command", "cmd", "line"]);
    if (cmd && !hasProgram) {
      return hallucinatedRunToSendTerminal(args, { name, ...args });
    }
  }
  const allowed = getAllowedToolNames();
  if (allowed.has(name)) return null;
  if (!HALLUCINATED_RUN_NAMES.has(name.toLowerCase())) return null;
  return hallucinatedRunToSendTerminal(args, { name, ...args });
}

/**
 * JSON like `{ "run_command": { "command": "python main.py download" } }` (invalid OpenAI shape;
 * real tools use `function.name` + `arguments`). Map inner object through the same terminal builder.
 */
function tryShorthandTopLevelToolJson(parsed: unknown): OllamaToolCall[] | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const o = parsed as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 1) return null;
  const key = keys[0];
  if (key !== "run_command" && key !== "run" && key !== "send_integrated_terminal") return null;
  const val = o[key];
  if (!val || typeof val !== "object" || Array.isArray(val)) return null;
  const syn = hallucinatedRunToSendTerminal(val as Record<string, unknown>, o);
  return syn ? [syn] : null;
}

function makeToCall(allowed: Set<string>) {
  return (o: unknown, i: number): OllamaToolCall | null => {
    if (!o || typeof o !== "object") return null;
    const r = o as Record<string, unknown>;
    const fn = r.function;
    let name: string | undefined;
    let args: unknown = r.arguments;

    if (typeof fn === "string" && fn) {
      name = fn;
      if (r.arguments !== undefined) args = r.arguments;
      else if (r.args !== undefined) args = r.args;
    } else if (typeof fn === "object" && fn && "name" in (fn as object)) {
      const f = fn as { name?: string; arguments?: unknown };
      if (typeof f.name === "string") name = f.name;
      if (f.arguments !== undefined) args = f.arguments;
    }
    if (!name && typeof r.name === "string") name = r.name;
    if (name && args == null) {
      if (r.args !== undefined) args = r.args;
      else if (r["arguments"] !== undefined) args = r["arguments"];
    }
    if (!name) return null;
    {
      const merged: Record<string, unknown> = {
        ...r,
        ...(args && typeof args === "object" && !Array.isArray(args)
          ? (args as Record<string, unknown>)
          : {}),
      };
      const fixed = canonicalizeHallucinatedToolName(name, merged);
      if (fixed !== name) {
        name = fixed;
      }
    }
    // Some models say "enrich" instead of enrich_ioc; map when args look like IOC enrichment.
    if (name.toLowerCase() === "enrich" && allowed.has("enrich_ioc")) {
      const rec =
        args && typeof args === "object" && !Array.isArray(args)
          ? (args as Record<string, unknown>)
          : null;
      if (rec && typeof rec.ioc === "string" && rec.ioc.trim() !== "") {
        name = "enrich_ioc";
      }
    }
    if (!allowed.has(name)) {
      if (HALLUCINATED_RUN_NAMES.has(name.toLowerCase())) {
        const syn = hallucinatedRunToSendTerminal(args, r);
        if (syn) return syn;
      }
      return null;
    }

    let argumentsValue: string | Record<string, unknown> | undefined;
    if (args == null) {
      argumentsValue = undefined;
    } else if (typeof args === "string") {
      argumentsValue = args;
    } else if (typeof args === "object" && !Array.isArray(args)) {
      argumentsValue = args as Record<string, unknown>;
    } else {
      return null;
    }

    return {
      id: `call-fallback-${i}-${Date.now()}`,
      function: {
        name,
        arguments: argumentsValue,
      },
    };
  };
}
