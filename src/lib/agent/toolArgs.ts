import { stripMarkdownCodeFenceFromToolArgs } from "./ollamaMessages";

/**
 * Ollama sometimes returns function.arguments as a JSON string, sometimes as an object.
 * If we only JSON.parse strings, object form becomes {} and paths are empty → "invalid path :".
 */
export function parseToolArguments(raw: unknown): Record<string, unknown> {
  if (raw == null) return {};
  if (typeof raw === "object" && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>) };
  }
  if (typeof raw === "string") {
    const s = stripMarkdownCodeFenceFromToolArgs(raw);
    if (!s) return {};
    try {
      const v = JSON.parse(s) as unknown;
      if (v && typeof v === "object" && !Array.isArray(v)) {
        return v as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  return {};
}

/** First matching string value for common key variants (model / schema drift). */
function pickString(obj: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v.trim() !== "") return v.trim();
  }
  return "";
}

export function coercePathArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "path",
    "filePath",
    "file_path",
    "filepath",
    "Path",
    "targetPath",
    "target_path",
    // Scan output uses relativePath; models sometimes copy it (only safe if absolute)
    "relativePath",
    "relative_path",
  ]);
}

/** `README.md` at workspace root is almost always wrong when the model meant a project README. */
export function isBareWorkspaceReadmePath(path: string): boolean {
  const n = path.replace(/^\.\/+/, "").trim();
  return n === "README.md";
}

/** Full file body for **write_text_file** (UTF-8). */
export function coerceFileContentArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "content",
    "text",
    "body",
    "value",
    "string",
  ]);
}

export function coerceProgramArg(args: Record<string, unknown>): string {
  // Do not treat `cmd` / `command` here — models put full shell lines there; use resolveRunCommandProgramAndArgv.
  return pickString(args, ["program", "Program", "executable"]);
}

/**
 * Resolves `run_command` / `run` shape: either `program` + `args`, or a single shell line in
 * `cmd` / `text` / `command` → `bash` + `["-c", line]`. Also fixes `program: "ls -la"` with no args.
 */
export function resolveRunCommandProgramAndArgv(
  args: Record<string, unknown>,
): { program: string; argv: string[] } | null {
  const explicitProg = pickString(args, ["program", "Program", "executable"]);
  const argv = getRunCommandArgv(args);

  if (explicitProg && argv.length > 0) {
    return { program: explicitProg, argv };
  }

  const shellLine = pickString(args, [
    "cmd",
    "text",
    "script",
    "shell",
    "command",
    "line",
    "shell_command",
  ]);
  const lineTrim = shellLine.trim();
  if (lineTrim) {
    return { program: "bash", argv: ["-c", lineTrim] };
  }

  if (explicitProg) {
    if (argv.length === 0 && /\s/.test(explicitProg)) {
      return { program: "bash", argv: ["-c", explicitProg.trim()] };
    }
    return { program: explicitProg, argv };
  }

  return null;
}

/** run_trusted_workflow */
export function coerceTrustedWorkflowArg(args: Record<string, unknown>): string {
  return pickString(args, ["workflow", "Workflow", "id", "name"]);
}

/** Optional IntelX seed: email / domain — `query` / `target` / `email` (first line only). */
export function coerceTrustedWorkflowQueryArg(
  args: Record<string, unknown>,
): string {
  return pickString(args, [
    "query",
    "Query",
    "target",
    "Target",
    "email",
    "Email",
    "intelx_query",
  ]);
}

/** IntelX piped mode: YYYY-MM-DD (optional; defaults in runner). */
export function coerceIntelxStartDateArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "intelx_start_date",
    "intelxStartDate",
    "start_date",
    "startDate",
  ]);
}

export function coerceIntelxEndDateArg(args: Record<string, unknown>): string {
  return pickString(args, ["intelx_end_date", "intelxEndDate", "end_date", "endDate"]);
}

export function coerceIntelxSearchLimitArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "intelx_search_limit",
    "intelxSearchLimit",
    "search_limit",
    "searchLimit",
  ]);
}

/** CVE piped main.py: YYYY-MM-DD after "search" (optional; defaults in runner). */
export function coerceCveStartDateArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "cve_start_date",
    "cveStartDate",
    "cve_start",
  ]);
}

export function coerceCveEndDateArg(args: Record<string, unknown>): string {
  return pickString(args, ["cve_end_date", "cveEndDate", "cve_end"]);
}

/** CVE main.py: CVSS v3 threshold line (e.g. `>7.0`) or blank. */
export function coerceCveCvssArg(args: Record<string, unknown>): string {
  return pickString(args, ["cve_cvss", "cveCvss", "cvss", "CVSS"]);
}

/** CVE main.py: CVSS v4 threshold line — sixth piped line; omit or blank = no threshold. */
export function coerceCveCvssV4Arg(args: Record<string, unknown>): string {
  return pickString(args, [
    "cve_cvss_v4",
    "cveCvssV4",
    "cve_cvssV4",
    "cvss_v4",
    "cvssV4",
  ]);
}

export function coerceCwdArg(
  args: Record<string, unknown>,
): string | null {
  const v = pickString(args, ["cwd", "Cwd", "workingDirectory", "working_directory"]);
  if (v === "") return null;
  // Models use placeholders instead of omitting optional cwd; default lets Tauri use workspace.
  const lower = v.toLowerCase();
  if (lower === "workspace_root" || lower === "workspaceroot" || lower === "<workspace>") {
    return null;
  }
  // Training/docs paths — not a real workspace on the user's machine; let Tauri use the project root.
  if (lower === "/workspace" || lower.startsWith("/workspace/")) {
    return null;
  }
  return v;
}

/** Models often send `arguments` (OpenAPI style) instead of `args` for argv. */
export function getRunCommandArgv(
  args: Record<string, unknown>,
): string[] {
  const raw =
    args.args ?? args.argv ?? args.Arguments ?? args["arguments"];
  if (Array.isArray(raw)) {
    return raw.map((a) => String(a));
  }
  return [];
}

const TERMINAL_TEXT_KEYS = [
  "text",
  "data",
  "input",
  "command",
  "line",
  "buffer",
] as const;

/**
 * One block of text to send to the integrated terminal PTY.
 * Must **not** use `trim()`: a trailing newline is what submits the line to the shell. We
 * `trimStart` only. Also fixes models that end with literal `\\` + `n` instead of a real `\n`.
 * If there is still no end-of-line, appends `\n` so the line runs without the user pressing Enter.
 */
export function coerceTerminalDataArg(args: Record<string, unknown>): string {
  let s = "";
  for (const k of TERMINAL_TEXT_KEYS) {
    const v = args[k];
    if (typeof v === "string" && v.length > 0) {
      s = v;
      break;
    }
  }
  if (s.length === 0) return "";
  s = s.replace(/^\s+/, "");
  // Some models end the string with two chars backslash + n (wrong) instead of a real newline.
  s = s.replace(/\\r\\n$/, "\r\n").replace(/\\n$/, "\n");
  if (!/[\n\r]\s*$/.test(s)) {
    s = s + "\n";
  }
  return s;
}

/**
 * Models often mistake `send_integrated_terminal` for `run_command` and pass `program` + `args`
 * instead of `text`. Reconstruct a single shell line so the PTY still receives something useful.
 */
export function terminalTextFromRunCommandStyleArgs(
  args: Record<string, unknown>,
): string | null {
  const resolved = resolveRunCommandProgramAndArgv(args);
  if (!resolved) return null;
  const words = [resolved.program, ...resolved.argv];
  return words
    .map((w) => (/\s/.test(w) ? `"${w.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : w))
    .join(" ");
}

/**
 * Many systems (notably macOS with Homebrew) expose **python3** on PATH but not **python**, so
 * README examples with `python main.py` fail with "command not found: python".
 */
export function preferPython3Command(line: string): string {
  let s = line;
  s = s.replace(/^python(\s)/m, "python3$1");
  s = s.replace(/&&\s*python(\s)/g, "&& python3$1");
  return s;
}

/**
 * Models sometimes put literal backslash-n in `text`; the shell receives two characters, not a newline.
 * Normalize common escape sequences before sending to the PTY.
 */
export function normalizeTerminalEscapeLiterals(data: string): string {
  if (!data.includes("\\")) return data;
  return data
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t");
}

/**
 * Shells only submit a line after Enter. Models often send a full command without trailing `\n`,
 * which leaves the line at the prompt until the user presses Return.
 */
export function ensurePtyLineSubmitted(data: string): string {
  if (data === "") return data;
  if (/\r?\n$/.test(data)) return data;
  return `${data}\n`;
}

/**
 * `analyze_workspace_run_requirements` — default to fast index; optional deep scan and cache control.
 * Uses snake_case in invoke to match the Rust `#[tauri::command]` parameters.
 */
export function parseAnalyzeWorkspaceCallArgs(
  args: Record<string, unknown>,
): {
  workflowRelativePath: string | null;
  fullWorkspace: boolean;
  useCache: boolean;
} {
  const w = pickString(args, [
    "workflowRelativePath",
    "workflow_relative_path",
    "workflow",
    "subfolder",
    "project",
    "projectPath",
  ]);
  const full =
    args.fullWorkspace === true ||
    args.full_workspace === true ||
    args.mode === "full" ||
    args.scan === "full" ||
    args.deep === true;
  const noCache =
    args.useCache === false ||
    args.use_cache === false ||
    args.noCache === true ||
    args.no_cache === true ||
    args.refresh === true ||
    args.force === true;
  return {
    workflowRelativePath: w || null,
    fullWorkspace: full,
    useCache: !noCache,
  };
}

/** IOC tool args: models sometimes use camelCase. */
export function pickOptString(
  args: Record<string, unknown>,
  keys: string[],
): string | undefined {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

function pickOptI64(
  args: Record<string, unknown>,
  keys: string[],
): number | undefined {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
    if (typeof v === "string" && v.trim() !== "" && /^-?\d+$/.test(v.trim())) {
      return parseInt(v.trim(), 10);
    }
  }
  return undefined;
}

/** Parse ioc_update / ioc_create–style optional string fields. */
export function parseIocStringFields(args: Record<string, unknown>): {
  value: string | undefined;
  iocType: string | undefined;
  source: string | undefined;
  campaignTag: string | undefined;
  profileId: string | undefined;
  id: string | undefined;
  json: string | undefined;
} {
  return {
    value: pickOptString(args, ["value", "ioc", "iocValue", "val", "indicator"]) ?? undefined,
    iocType: pickOptString(args, [
      "ioc_type",
      "iocType",
      "type",
      "ioc_type_hint",
    ]),
    source: pickOptString(args, ["source", "src"]),
    campaignTag: pickOptString(args, ["campaign_tag", "campaignTag", "campaign"]),
    profileId: pickOptString(args, ["profile_id", "profileId"]),
    id: pickOptString(args, ["id", "ioc_id", "iocId"]),
    json: pickOptString(args, [
      "json",
      "stix",
      "misp",
      "data",
      "content",
      "body",
      "raw",
    ]),
  };
}

export function parseIocSearchArgs(
  args: Record<string, unknown>,
): {
  valueContains: string | undefined;
  iocType: string | undefined;
  campaign: string | undefined;
  source: string | undefined;
  profileId: string | undefined;
  allProfiles: boolean;
  includeFalsePositives: boolean;
  limit: number | undefined;
} {
  const all =
    args.all_profiles === true ||
    args.allProfiles === true ||
    args.all_profiles === "true" ||
    args.allProfiles === "true";
  const includeFp =
    args.include_false_positives === true ||
    args.includeFalsePositives === true ||
    args.include_false_positives === "true" ||
    args.includeFalsePositives === "true";
  return {
    valueContains: pickOptString(args, [
      "value_contains",
      "valueContains",
      "q",
      "query",
    ]),
    iocType: pickOptString(args, ["ioc_type", "iocType", "type"]),
    campaign: pickOptString(args, ["campaign", "campaign_tag", "campaignTag"]),
    source: pickOptString(args, ["source", "src"]),
    profileId: pickOptString(args, ["profile_id", "profileId"]),
    allProfiles: all,
    includeFalsePositives: includeFp,
    limit: pickOptI64(args, ["limit", "max", "count"]),
  };
}
