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

export function coerceProgramArg(args: Record<string, unknown>): string {
  return pickString(args, ["program", "Program", "executable", "cmd", "command"]);
}

export function coerceCwdArg(
  args: Record<string, unknown>,
): string | null {
  const v = pickString(args, ["cwd", "Cwd", "workingDirectory", "working_directory"]);
  return v === "" ? null : v;
}

/** One block of text to send to the integrated terminal PTY. */
export function coerceTerminalDataArg(args: Record<string, unknown>): string {
  return pickString(args, [
    "text",
    "data",
    "input",
    "command",
    "line",
    "buffer",
  ]);
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
