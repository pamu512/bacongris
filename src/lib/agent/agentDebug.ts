/**
 * Agent / Ollama / tool trace logging. Enable in production with:
 *   localStorage.setItem("bacongrisAgentDebug", "1")
 * Disable in dev with:
 *   localStorage.setItem("bacongrisAgentDebug", "0")
 * In Vite dev builds, logging is on by default unless disabled above.
 */
export function shouldLogAgent(): boolean {
  try {
    if (typeof localStorage !== "undefined") {
      const v = localStorage.getItem("bacongrisAgentDebug");
      if (v === "0" || v === "false") return false;
      if (v === "1" || v === "true") return true;
    }
  } catch {
    /* private mode, etc. */
  }
  return import.meta.env.DEV;
}

export function agentLog(...args: unknown[]): void {
  if (!shouldLogAgent()) return;
  console.log("[bacongris:agent]", ...args);
}

export function agentWarn(...args: unknown[]): void {
  if (!shouldLogAgent()) return;
  console.warn("[bacongris:agent]", ...args);
}

export function summarizeOllamaToolCalls(
  calls: { function?: { name?: string } }[] | undefined,
): string {
  if (!calls?.length) return "(none)";
  return calls.map((c) => c.function?.name ?? "?").join(", ");
}
