/**
 * Phrases that start a bundled workflow **without** calling the LLM.
 * Keeps “run cve” / “run intelx” from spiraling into unrelated tools (e.g. enrich_*).
 */
export type DirectTrustedWorkflowId = "intelx" | "cve";

export type DirectTrustedWorkflowMatch = {
  id: DirectTrustedWorkflowId;
  /** Piped to `run_trusted_workflow` (IntelX seed, CVE vendor line, etc.); `null` = interactive */
  query: string | null;
};

export function matchDirectTrustedWorkflowShortcut(
  text: string,
  ctx: { hasInlineAttachments: boolean; hasWorkspaceUploads: boolean },
): DirectTrustedWorkflowMatch | null {
  if (ctx.hasInlineAttachments || ctx.hasWorkspaceUploads) return null;
  // Treat "cve/nvd" and "cve\\nvd" like "cve nvd" so shortcuts match (user often types slashes).
  const t = text
    .trim()
    .toLowerCase()
    .replace(/\\/g, " ")
    .replace(/\//g, " ")
    .replace(/\s+/g, " ");
  if (!t) return null;

  const cveExact = new Set([
    "run cve",
    "start cve",
    "run cve nvd",
    "start cve nvd",
    "run nvd",
    "start nvd",
  ]);
  if (cveExact.has(t)) {
    return { id: "cve", query: null };
  }

  const intelxExact = new Set(["run intelx", "start intelx"]);
  if (intelxExact.has(t)) {
    return { id: "intelx", query: null };
  }

  // "run intelx for user@x.com" / "start intelx with …" (must run before the single-token form)
  const intelxFor = t.match(/^(run|start) intelx (?:for|with) (.+)$/);
  if (intelxFor) {
    const q = intelxFor[2].trim();
    if (q) {
      return { id: "intelx", query: q };
    }
  }

  // "run intelx user@x.com" — second word is the query (not the keywords above)
  const intelxToken = t.match(/^(run|start) intelx (\S+)$/);
  if (intelxToken) {
    const second = intelxToken[2];
    if (second !== "for" && second !== "with" && second !== "nvd") {
      return { id: "intelx", query: second };
    }
  }

  const cveFor = t.match(/^(run|start) cve(?: nvd)? (?:for|with) (.+)$/);
  if (cveFor) {
    const q = cveFor[2].trim();
    if (q) {
      return { id: "cve", query: q };
    }
  }

  const cveToken = t.match(/^(run|start) cve (\S+)$/);
  if (cveToken) {
    const second = cveToken[2];
    if (second === "nvd" || second === "for" || second === "with") {
      return null;
    }
    return { id: "cve", query: second };
  }

  const cveNvdToken = t.match(/^(run|start) cve nvd (\S+)$/);
  if (cveNvdToken) {
    const third = cveNvdToken[2];
    if (third === "for" || third === "with") {
      return null;
    }
    return { id: "cve", query: third };
  }

  return null;
}
