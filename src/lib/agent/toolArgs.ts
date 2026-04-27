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
    const s = raw.trim();
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
  return pickString(args, ["program", "Program", "executable", "cmd", "command"]);
}

export function coerceCwdArg(
  args: Record<string, unknown>,
): string | null {
  const v = pickString(args, ["cwd", "Cwd", "workingDirectory", "working_directory"]);
  return v === "" ? null : v;
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
