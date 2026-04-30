/**
 * Aggregates local CTI maintenance state and artifact samples for system-prompt injection.
 *
 * **Note on `fs/promises`:** The Bacongris UI is a Tauri webview, not Node — there is no `fs` module
 * in the browser bundle. File access uses the same non-blocking Tauri `invoke` paths as the rest
 * of the app (`read_text_file`, `list_directory` with `modifiedMs`), which is async I/O suitable
 * for the main thread.
 */

import { invoke } from "@tauri-apps/api/core";
import { MaintenanceManager } from "./maintenance";
import type { DirListRow, EnvironmentInfo } from "./maintenance";
import { maxFileModifiedMsUnder } from "./maintenance";
import { VISUAL_WORKSPACE_MAP } from "./visualWorkspaceMap";

const CVE_OUTPUT_REL = `${VISUAL_WORKSPACE_MAP.VULNS_CVE}/output_result`;
const INTELX_CSV_REL = VISUAL_WORKSPACE_MAP.LEAKS_PII_CSV_OUTPUT;

/** Rough ceiling so injected text stays under ~1k tokens (local Ollama). */
export const MAX_LOCAL_INJECTION_CHARS = 3200;

/** Above this size (UTF-8 bytes), sample header + 5 data rows (or JSON equivalent). */
export const ARTIFACT_COMPACT_BYTES = 2048;

const ARTIFACT_EXTS = new Set([
  ".json",
  ".ndjson",
  ".csv",
  ".txt",
  ".log",
]);

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n\n…(truncated)`;
}

function tailLines(text: string, lineCount: number): string {
  const n = Math.max(1, Math.min(lineCount, 200));
  const lines = text.split(/\r?\n/);
  if (lines.length <= n) return text.trimEnd();
  return lines.slice(-n).join("\n").trimEnd();
}

function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

function wrapCdata(s: string): string {
  return `<![CDATA[${s.replace(/]]>/g, "]]]]><![CDATA[>")}]]>`;
}

/**
 * If artifact text exceeds ~2KB, return header + 5 "rows" (CSV/NDJSON) or a compact JSON slice;
 * otherwise return full `raw`.
 */
export function truncateArtifactText(raw: string, fileName: string): string {
  if (utf8ByteLength(raw) <= ARTIFACT_COMPACT_BYTES) return raw;
  const low = fileName.toLowerCase();
  const ext = low.includes(".") ? low.slice(low.lastIndexOf(".")) : "";
  if (ext === ".csv" || (raw.includes(",") && raw.split(/\r?\n|\n/).length > 1)) {
    const lines = raw.split(/\r?\n/);
    const header = lines[0] ?? "";
    const dataRows = lines.slice(1, 6);
    return `${header}\n${dataRows.join("\n")}\n\n…(file >2KB: header + top 5 rows only; full file not shown)`;
  }
  if (ext === ".ndjson") {
    const lines = raw.split(/\r?\n/).filter(Boolean);
    return `${lines.slice(0, 6).join("\n")}\n\n…(ndjson >2KB: first 6 lines only)`;
  }
  if (ext === ".json" || (raw.trim().startsWith("{") || raw.trim().startsWith("["))) {
    const t = raw.trim();
    try {
      const j: unknown = JSON.parse(t);
      if (Array.isArray(j)) {
        return (
          JSON.stringify(j.slice(0, 5), null, 2) +
          "\n\n…(array >2KB: first 5 items only)"
        );
      }
      if (j && typeof j === "object") {
        const o = j as Record<string, unknown>;
        const keys = Object.keys(o).slice(0, 5);
        const out: Record<string, unknown> = {};
        for (const k of keys) out[k] = o[k];
        return (
          JSON.stringify(out, null, 2) +
          "\n\n…(object >2KB: first 5 properties only)"
        );
      }
    } catch {
      return `${raw.slice(0, 1200)}\n\n…(json >2KB: parse failed; head only)`;
    }
  }
  const lines = raw.split(/\r?\n/);
  return `${lines[0] ?? ""}\n${lines.slice(1, 6).join("\n")}\n\n…(text >2KB: first line + 5 lines only)`;
}

async function getWorkspaceRoot(): Promise<string | null> {
  try {
    const env = await invoke<EnvironmentInfo>("get_environment");
    return env.workspaceRoot?.replace(/\/+$/, "") || null;
  } catch {
    return null;
  }
}

async function listDirAbs(absPath: string): Promise<DirListRow[]> {
  return invoke<DirListRow[]>("list_directory", { path: absPath });
}

/**
 * Newest file under `relToWorkspace` matching ARTIFACT_EXTS, by `modifiedMs`.
 * Returns path relative to workspace (forward slashes).
 */
export async function findNewestArtifactFile(
  workspaceRoot: string,
  relToWorkspace: string,
): Promise<{ relPath: string; modifiedMs: number } | null> {
  const base = `${workspaceRoot}/${relToWorkspace}`.replace(/\/+$/, "");
  let best: { relPath: string; modifiedMs: number } | null = null;
  const rootPrefix = workspaceRoot.replace(/\/+$/, "");
  const stack: string[] = [base];
  while (stack.length) {
    const dir = stack.pop()!;
    let rows: DirListRow[];
    try {
      rows = await listDirAbs(dir);
    } catch {
      continue;
    }
    for (const row of rows) {
      const child = `${dir}/${row.name}`;
      if (row.isDir) {
        stack.push(child);
        continue;
      }
      const low = row.name.toLowerCase();
      const ext = low.includes(".")
        ? low.slice(low.lastIndexOf("."))
        : "";
      if (!ARTIFACT_EXTS.has(ext)) continue;
      const m = row.modifiedMs;
      if (typeof m !== "number" || !Number.isFinite(m)) continue;
      const rel = child.startsWith(rootPrefix)
        ? child.slice(rootPrefix.length).replace(/^\/+/, "")
        : child;
      if (!best || m > best.modifiedMs) best = { relPath: rel, modifiedMs: m };
    }
  }
  return best;
}

/**
 * Summary of the last three successful project syncs (ISO timestamp + display name).
 */
export async function getFreshnessContext(): Promise<string> {
  const state = await MaintenanceManager.getState();
  const rows = Object.values(state.projects)
    .filter((p) => p.lastSuccessfulSync)
    .map((p) => ({
      displayName: p.displayName || p.projectId,
      t: Date.parse(p.lastSuccessfulSync!),
    }))
    .filter((p) => Number.isFinite(p.t))
    .sort((a, b) => b.t - a.t)
    .slice(0, 3);

  if (rows.length === 0) {
    return "No successful maintenance syncs recorded in maintenance_status.json yet.";
  }
  return rows
    .map(
      (r) =>
        `- **${r.displayName}** — last OK sync: \`${new Date(r.t).toISOString()}\``,
    )
    .join("\n");
}

/**
 * Between CVE `output_result/` and Intelx `csv_output/`, pick the project that was updated most
 * recently (by maintenance `lastSuccessfulSync`, else by on-disk file mtimes), then return the
 * last `limit` text lines of that artifact.
 */
export async function getLatestFindings(limit: number = 10): Promise<string> {
  const root = await getWorkspaceRoot();
  if (!root) {
    return "(workspace not available; cannot read artifacts.)";
  }
  const state = await MaintenanceManager.getState();
  const cveId = VISUAL_WORKSPACE_MAP.VULNS_CVE;
  const intelId = VISUAL_WORKSPACE_MAP.LEAKS_PII;
  const cveEntry = state.projects[cveId];
  const intelEntry = state.projects[intelId];
  const cveT = cveEntry?.lastSuccessfulSync
    ? Date.parse(cveEntry.lastSuccessfulSync)
    : 0;
  const intelT = intelEntry?.lastSuccessfulSync
    ? Date.parse(intelEntry.lastSuccessfulSync)
    : 0;
  let useCve: boolean;
  if (cveT > intelT) useCve = true;
  else if (intelT > cveT) useCve = false;
  else {
    const [cveM, intelM] = await Promise.all([
      maxFileModifiedMsUnder(root, CVE_OUTPUT_REL),
      maxFileModifiedMsUnder(root, INTELX_CSV_REL),
    ]);
    useCve = cveM >= intelM;
  }

  const relDir = useCve ? CVE_OUTPUT_REL : INTELX_CSV_REL;
  const label = useCve ? cveId : `IntelX (${intelId})`;

  let file = await findNewestArtifactFile(root, relDir);
  if (!file) {
    const altRel = useCve ? INTELX_CSV_REL : CVE_OUTPUT_REL;
    const other = await findNewestArtifactFile(root, altRel);
    if (other) {
      return await readTailFromRelPath(
        root,
        other.relPath,
        `Fallback (no file in ${relDir}): **${other.relPath}**`,
        limit,
      );
    }
    return `No CSV/JSON/log artifacts found under \`${relDir}/\` or \`${altRel}/\` — run workflows first.`;
  }
  return await readTailFromRelPath(
    root,
    file.relPath,
    `**${label}** — \`${file.relPath}\` (mtime ${new Date(
      file.modifiedMs,
    ).toISOString()})`,
    limit,
  );
}

async function readTailFromRelPath(
  root: string,
  rel: string,
  label: string,
  limit: number,
): Promise<string> {
  const fileName = rel.split(/[/\\]/).pop() ?? "artifact";
  const full = rel.startsWith(root) ? rel : `${root}/${rel.replace(/^\/+/, "")}`;
  let text: string;
  try {
    text = await invoke<string>("read_text_file", { path: full });
  } catch (e) {
    return `${label}\n\n(read error: ${
      e instanceof Error ? e.message : String(e)
    })`;
  }
  let body: string;
  if (utf8ByteLength(text) > ARTIFACT_COMPACT_BYTES) {
    body = truncateArtifactText(text, fileName);
  } else {
    const n = Math.max(1, limit);
    body = tailLines(text, n);
  }
  return `${label}\n\n\`\`\`\n${body}\n\`\`\``;
}

/**
 * Maintenance + artifact sample wrapped for system prompt (after system identity).
 */
export async function buildLocalIntelligenceInjection(
  maxChars: number = MAX_LOCAL_INJECTION_CHARS,
): Promise<string> {
  let block = "";
  try {
    const [fresh, findings] = await Promise.all([
      getFreshnessContext(),
      getLatestFindings(10),
    ]);
    block = `<intelligence_context>
<sync_status>
${wrapCdata(fresh)}
</sync_status>
<latest_records>
${wrapCdata(findings)}
</latest_records>
</intelligence_context>`;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    block = `<intelligence_context>
<sync_status>
${wrapCdata(`(aggregator error: ${msg})`)}
</sync_status>
<latest_records></latest_records>
</intelligence_context>`;
  }
  return truncate(block, maxChars);
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * `true` if there is no successful maintenance sync, or the newest sync is older than `maxAgeHours` (default 24).
 */
export async function isLocalIntelligenceStale(
  maxAgeHours: number = 24,
): Promise<boolean> {
  const state = await MaintenanceManager.getState();
  const times = Object.values(state.projects)
    .map((p) => (p.lastSuccessfulSync ? Date.parse(p.lastSuccessfulSync) : 0))
    .filter((t) => t > 0);
  if (times.length === 0) return true;
  const newest = Math.max(...times);
  return Date.now() - newest > maxAgeHours * MS_PER_DAY;
}

/** @internal for tests: pick CVE vs IntelX folder from maintenance + mtimes. */
export async function pickCveOrIntelXProjectForSample(): Promise<"cve" | "intelx"> {
  const root = await getWorkspaceRoot();
  if (!root) return "intelx";
  const state = await MaintenanceManager.getState();
  const cveId = VISUAL_WORKSPACE_MAP.VULNS_CVE;
  const intelId = VISUAL_WORKSPACE_MAP.LEAKS_PII;
  const cveS = state.projects[cveId]?.lastSuccessfulSync;
  const intelS = state.projects[intelId]?.lastSuccessfulSync;
  const cveT = cveS ? Date.parse(cveS) : 0;
  const intelT = intelS ? Date.parse(intelS) : 0;
  if (cveT > intelT) return "cve";
  if (intelT > cveT) return "intelx";
  const [a, b] = await Promise.all([
    maxFileModifiedMsUnder(root, CVE_OUTPUT_REL),
    maxFileModifiedMsUnder(root, INTELX_CSV_REL),
  ]);
  return a >= b ? "cve" : "intelx";
}
