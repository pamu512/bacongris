import { invoke } from "@tauri-apps/api/core";
import { syncCtiVaultCvesToAppNow } from "./ctiVaultSync";
import { VISUAL_WORKSPACE_MAP } from "./visualWorkspaceMap";

export const MAINTENANCE_JSON_VERSION = "1";

/** Default wait after terminal / trusted-workflow dispatch before artifact checks. */
export const DEFAULT_FILE_HANDSHAKE_MS = 5 * 60 * 1000;

let fileHandshakeMsOverride: number | null = null;

/** Narrow windows in tests; call `resetMaintenanceTestHooks()` in `afterEach`. */
export function setFileHandshakeMsForTests(ms: number): void {
  fileHandshakeMsOverride = ms;
}

export function resetMaintenanceTestHooks(): void {
  fileHandshakeMsOverride = null;
}

export function getFileHandshakeMs(): number {
  return fileHandshakeMsOverride ?? DEFAULT_FILE_HANDSHAKE_MS;
}

async function handshakeDelay(): Promise<void> {
  const ms = getFileHandshakeMs();
  if (ms <= 0) return;
  await new Promise<void>((r) => setTimeout(r, ms));
}

export interface ProjectMaintenanceEntry {
  projectId: string;
  displayName: string;
  lastSuccessfulSync: string | null;
  nextScheduledSync: string;
  currentStatus: "idle" | "running" | "degraded" | "failed" | "stale";
  lastExitCode: number | null;
  lastErrorLog: string | null;
  metrics: {
    totalRuns: number;
    failureCount: number;
    averageDurationMs: number;
  };
  artifacts: {
    expectedOutputFile: string;
    lastVerifiedExistence: boolean;
  };
}

export interface MaintenanceStatus {
  version: string;
  globalLock: boolean;
  projects: Record<string, ProjectMaintenanceEntry>;
}

export interface EnvironmentInfo {
  os: string;
  arch: string;
  family: string;
  homeDir: string | null;
  tempDir: string | null;
  cwd: string;
  workspaceRoot: string;
  scriptsDir: string;
  workspaceIsCustom: boolean;
  python3Version: string | null;
  pythonVersion: string | null;
  /** `docker --version` on PATH, or null if the CLI is missing. */
  dockerVersion: string | null;
}

/** NVD / CVE: UI treats last sync older than this as a stale local database. */
export const CVE_STALE_MAX_AGE_MS = 12 * 60 * 60 * 1000;

export function isCveDatabaseStale(lastSuccessfulSyncIso: string | null): boolean {
  if (!lastSuccessfulSyncIso) return true;
  const t = Date.parse(lastSuccessfulSyncIso);
  if (!Number.isFinite(t)) return true;
  return Date.now() - t > CVE_STALE_MAX_AGE_MS;
}

export interface DirListRow {
  name: string;
  isDir: boolean;
  modifiedMs?: number | null;
}

const MAINTENANCE_FILE = "maintenance_status.json";
const CHECK_INTERVAL_MS = 15 * 60 * 1000;

const INTELX_CSV_OUTPUT_REL = VISUAL_WORKSPACE_MAP.LEAKS_PII_CSV_OUTPUT;

const INTELX_MAINTENANCE_QUERY = "bacongris-maintenance-probe@invalid";

type ProjectKind = "run_command" | "terminal_workers" | "trusted_workflow_intelx";

interface ProjectRecipe {
  projectId: string;
  displayName: string;
  artifactRelPath: string;
  intervalMs: number;
  kind: ProjectKind;
}

/** Order used by scheduled + “run all”: ASM → CVE → IOC, then IntelX (IntelX is not in “update all datasets”). */
const PROJECT_RECIPES: ProjectRecipe[] = [
  {
    projectId: VISUAL_WORKSPACE_MAP.RECON_ASM,
    displayName: "ASM Fetch",
    artifactRelPath: `${VISUAL_WORKSPACE_MAP.RECON_ASM}/README.md`,
    intervalMs: 7 * 24 * 60 * 60 * 1000,
    kind: "run_command",
  },
  {
    projectId: VISUAL_WORKSPACE_MAP.VULNS_CVE,
    displayName: "CVE / NVD",
    artifactRelPath: `${VISUAL_WORKSPACE_MAP.VULNS_CVE}/README.md`,
    intervalMs: 12 * 60 * 60 * 1000,
    kind: "run_command",
  },
  {
    projectId: VISUAL_WORKSPACE_MAP.FEED_INGEST,
    displayName: "IOCs Crawler",
    artifactRelPath: VISUAL_WORKSPACE_MAP.FEED_INGEST,
    intervalMs: 60 * 60 * 1000,
    kind: "terminal_workers",
  },
  {
    projectId: VISUAL_WORKSPACE_MAP.LEAKS_PII,
    displayName: "IntelX",
    artifactRelPath: INTELX_CSV_OUTPUT_REL,
    intervalMs: 24 * 60 * 60 * 1000,
    kind: "trusted_workflow_intelx",
  },
];

/** True if any known CTI row is failed/degraded/stale, CVE is past the window, or a row is missing. */
export function isAnyCtiMaintenanceStale(state: MaintenanceStatus | null | undefined): boolean {
  if (!state?.projects) return true;
  for (const recipe of PROJECT_RECIPES) {
    const e = state.projects[recipe.projectId];
    if (!e) return true;
    if (
      e.currentStatus === "stale" ||
      e.currentStatus === "failed" ||
      e.currentStatus === "degraded"
    ) {
      return true;
    }
    if (recipe.projectId === VISUAL_WORKSPACE_MAP.VULNS_CVE && isCveDatabaseStale(e.lastSuccessfulSync)) {
      return true;
    }
  }
  return false;
}

function isoFromMs(ms: number): string {
  return new Date(ms).toISOString();
}

function msFromIso(iso: string | null | undefined, fallbackMs: number): number {
  if (!iso) return fallbackMs;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : fallbackMs;
}

function defaultEntry(recipe: ProjectRecipe): ProjectMaintenanceEntry {
  const now = Date.now();
  return {
    projectId: recipe.projectId,
    displayName: recipe.displayName,
    lastSuccessfulSync: null,
    nextScheduledSync: isoFromMs(now),
    currentStatus: "idle",
    lastExitCode: null,
    lastErrorLog: null,
    metrics: { totalRuns: 0, failureCount: 0, averageDurationMs: 0 },
    artifacts: {
      expectedOutputFile: recipe.artifactRelPath,
      lastVerifiedExistence: false,
    },
  };
}

interface LegacyProjectRow {
  last_sync_timestamp: number | null;
  success_rate: number;
  next_scheduled_run: number | null;
  status: "idle" | "running" | "error";
  last_error?: string;
}

interface LegacyMaintenanceFile {
  projects: Record<string, LegacyProjectRow>;
}

function isLegacyMaintenanceFile(x: unknown): x is LegacyMaintenanceFile {
  if (!x || typeof x !== "object") return false;
  const p = (x as { projects?: unknown }).projects;
  if (!p || typeof p !== "object") return false;
  for (const row of Object.values(p)) {
    if (
      row &&
      typeof row === "object" &&
      "last_sync_timestamp" in row &&
      "next_scheduled_run" in row &&
      "success_rate" in row
    ) {
      return true;
    }
  }
  return false;
}

function legacyStatusToNew(s: LegacyProjectRow): Pick<
  ProjectMaintenanceEntry,
  | "lastSuccessfulSync"
  | "nextScheduledSync"
  | "currentStatus"
  | "lastExitCode"
  | "lastErrorLog"
  | "metrics"
> {
  let currentStatus: ProjectMaintenanceEntry["currentStatus"] = "idle";
  if (s.status === "running") currentStatus = "running";
  else if (s.status === "error") currentStatus = "failed";

  const failEst = Math.max(0, Math.min(100, 100 - Math.round(s.success_rate))) / 10;
  const failureCount = Math.min(100, Math.round(failEst * 3));
  const totalRuns = Math.max(failureCount, Math.round((s.success_rate / 100) * 20));

  return {
    lastSuccessfulSync:
      s.last_sync_timestamp != null ? isoFromMs(s.last_sync_timestamp) : null,
    nextScheduledSync: isoFromMs(s.next_scheduled_run ?? Date.now()),
    currentStatus,
    lastExitCode: s.status === "error" ? -1 : null,
    lastErrorLog: s.last_error ?? null,
    metrics: {
      totalRuns,
      failureCount,
      averageDurationMs: 0,
    },
  };
}

function migrateLegacyFile(legacy: LegacyMaintenanceFile): MaintenanceStatus {
  const projects: Record<string, ProjectMaintenanceEntry> = {};
  for (const recipe of PROJECT_RECIPES) {
    const row = legacy.projects[recipe.projectId];
    const base = defaultEntry(recipe);
    if (row) {
      Object.assign(base, legacyStatusToNew(row));
    }
    base.artifacts.expectedOutputFile = recipe.artifactRelPath;
    projects[recipe.projectId] = base;
  }
  return {
    version: MAINTENANCE_JSON_VERSION,
    globalLock: false,
    projects,
  };
}

function normalizeParsedStatus(raw: MaintenanceStatus): MaintenanceStatus {
  const projects: Record<string, ProjectMaintenanceEntry> = { ...raw.projects };
  for (const recipe of PROJECT_RECIPES) {
    if (!projects[recipe.projectId]) {
      projects[recipe.projectId] = defaultEntry(recipe);
    } else {
      const e = projects[recipe.projectId];
      e.projectId = recipe.projectId;
      if (!e.displayName) e.displayName = recipe.displayName;
      if (!e.artifacts?.expectedOutputFile) {
        e.artifacts = { ...e.artifacts, expectedOutputFile: recipe.artifactRelPath };
      }
    }
  }
  return {
    version: MAINTENANCE_JSON_VERSION,
    globalLock: Boolean(raw.globalLock),
    projects,
  };
}

export function parseMaintenanceStatusJson(text: string): MaintenanceStatus {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return normalizeParsedStatus({
      version: MAINTENANCE_JSON_VERSION,
      globalLock: false,
      projects: {},
    });
  }

  if (isLegacyMaintenanceFile(parsed)) {
    return migrateLegacyFile(parsed);
  }

  if (
    parsed &&
    typeof parsed === "object" &&
    "projects" in parsed &&
    typeof (parsed as MaintenanceStatus).projects === "object"
  ) {
    const m = parsed as MaintenanceStatus;
    return normalizeParsedStatus({
      version: m.version || MAINTENANCE_JSON_VERSION,
      globalLock: Boolean(m.globalLock),
      projects: m.projects || {},
    });
  }

  return normalizeParsedStatus({
    version: MAINTENANCE_JSON_VERSION,
    globalLock: false,
    projects: {},
  });
}

function recordRunMetrics(
  entry: ProjectMaintenanceEntry,
  durationMs: number,
  success: boolean,
): void {
  entry.metrics.totalRuns += 1;
  if (!success) entry.metrics.failureCount += 1;
  const n = entry.metrics.totalRuns;
  entry.metrics.averageDurationMs =
    n === 1
      ? durationMs
      : Math.round(
          entry.metrics.averageDurationMs + (durationMs - entry.metrics.averageDurationMs) / n,
        );
}

async function listDirAbs(absPath: string): Promise<DirListRow[]> {
  return invoke<DirListRow[]>("list_directory", { path: absPath });
}

/** Deepest max mtime of files under `relDir` (recursive); 0 if no files or missing dir. Exported for tests. */
export async function maxFileModifiedMsUnder(
  workspaceRoot: string,
  relDir: string,
): Promise<number> {
  const base = `${workspaceRoot}/${relDir}`.replace(/\/+$/, "");
  let max = 0;
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
      if (row.isDir) stack.push(child);
      else {
        const m = row.modifiedMs;
        if (typeof m === "number" && Number.isFinite(m)) max = Math.max(max, m);
      }
    }
  }
  return max;
}

/** True when `csv_output` has no entries, no file mtimes increased, or listing failed. */
export function intelxArtifactLooksStale(params: {
  baselineMaxMtimeMs: number;
  rowsAtRoot: DirListRow[];
  maxMtimeAfterMs: number;
}): boolean {
  if (params.rowsAtRoot.length === 0) return true;
  if (params.maxMtimeAfterMs <= params.baselineMaxMtimeMs) return true;
  return false;
}

export class MaintenanceManager {
  private static intervalId: number | null = null;
  private static isRunning = false;

  static async getState(): Promise<MaintenanceStatus> {
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      const path = `${env.workspaceRoot}/${MAINTENANCE_FILE}`;
      const content = await invoke<string>("read_text_file", { path });
      return parseMaintenanceStatusJson(content);
    } catch {
      return normalizeParsedStatus({
        version: MAINTENANCE_JSON_VERSION,
        globalLock: false,
        projects: {},
      });
    }
  }

  static async saveState(state: MaintenanceStatus): Promise<void> {
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      const path = `${env.workspaceRoot}/${MAINTENANCE_FILE}`;
      const normalized = normalizeParsedStatus(state);
      await invoke("write_text_file", {
        path,
        content: JSON.stringify(normalized, null, 2),
      });
    } catch (e) {
      console.error("Failed to save maintenance state:", e);
    }
  }

  static async start(): Promise<void> {
    if (this.intervalId !== null) return;
    void this.runChecks();
    this.intervalId = window.setInterval(() => {
      void this.runChecks();
    }, CHECK_INTERVAL_MS);
  }

  static stop(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /** Runs one maintenance pass (used by timers and tests). */
  static async runMaintenanceCycleNow(): Promise<void> {
    await this.runChecks({ force: false });
  }

  /**
   * **Update all datasets (maintenance):** runs **ASM → CVE → IOC** in sequence (ignores
   * `nextScheduledSync`). **IntelX** is not part of this action — it only runs on its own
   * schedule / tooling. Can take a long time.
   */
  static async runAllMaintenanceJobsNow(): Promise<void> {
    await this.runChecks({ force: true, coreDatasetsOnly: true });
  }

  private static async runChecks(
    options?: { force?: boolean; coreDatasetsOnly?: boolean },
  ): Promise<void> {
    const force = options?.force === true;
    const coreOnly = options?.coreDatasetsOnly === true;
    const recipeList = coreOnly
      ? PROJECT_RECIPES.filter((r) => r.projectId !== VISUAL_WORKSPACE_MAP.LEAKS_PII)
      : PROJECT_RECIPES;
    if (this.isRunning) {
      if (force) {
        throw new Error(
          "A maintenance run is already in progress in this window. Wait for it to finish, then try again.",
        );
      }
      return;
    }
    this.isRunning = true;
    let state = await this.getState();
    if (state.globalLock) {
      // A prior run may have been killed after setting the lock, leaving it stuck. While
      // `isRunning` is false we are not mid-flight, so the file lock is safe to clear.
      state.globalLock = false;
      await this.saveState(state);
      state = await this.getState();
    }
    state.globalLock = true;
    await this.saveState(state);
    try {
      state = await this.getState();
      const now = Date.now();

      for (const recipe of recipeList) {
        const entry = state.projects[recipe.projectId];
        if (!entry) continue;
        const due = msFromIso(entry.nextScheduledSync, now) <= now;
        if (!due && !force) continue;

        if (recipe.kind === "run_command") {
          if (recipe.projectId === VISUAL_WORKSPACE_MAP.VULNS_CVE) {
            await this.runCVEUpdate(state);
          } else if (recipe.projectId === VISUAL_WORKSPACE_MAP.RECON_ASM) {
            await this.runASMUpdate(state);
          }
        } else if (recipe.kind === "terminal_workers") {
          await this.runIOCsUpdate(state);
        } else if (recipe.kind === "trusted_workflow_intelx") {
          await this.runIntelxUpdate(state);
        }
        state = await this.getState();
      }
    } catch (e) {
      console.error("Maintenance check failed:", e);
    } finally {
      state = await this.getState();
      state.globalLock = false;
      await this.saveState(state);
      this.isRunning = false;
    }
  }

  private static async runCVEUpdate(state: MaintenanceStatus): Promise<void> {
    const recipe = PROJECT_RECIPES.find((r) => r.projectId === VISUAL_WORKSPACE_MAP.VULNS_CVE)!;
    const proj = recipe.projectId;
    const entry = state.projects[proj];
    entry.currentStatus = "running";
    entry.lastErrorLog = null;
    await this.saveState(state);

    const t0 = performance.now();
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      if (!env.python3Version && !env.pythonVersion) {
        throw new Error("Python is not available");
      }

      // Interactive NVD main.py: first successful maintenance run should send `download`,
      // every later run sends `update` (see project prompt: download / update / search).
      const nvdMenuLine = entry.lastSuccessfulSync ? "update" : "download";
      // Prefer project-local venv: some trees use `bin/python`, others `.venv/bin/python` only.
      const cmd = [
        `cd ${proj}`,
        `if [ -x bin/python ]; then echo ${nvdMenuLine} | bin/python main.py`,
        `elif [ -x .venv/bin/python ]; then echo ${nvdMenuLine} | .venv/bin/python main.py`,
        `else echo ${nvdMenuLine} | python3 main.py; fi`,
      ].join("; ");
      // NVD download over Tor can exceed the default Settings run_command limit (e.g. 120s).
      const result = await invoke<{
        exitCode: number | null;
        stdout: string;
        stderr: string;
        timedOut?: boolean;
      }>("run_command", {
        program: "bash",
        args: ["-c", cmd],
        cwd: env.workspaceRoot,
        // Must match Rust `run_command(..., timeout_override_secs: Option<u64>)` — camelCase is not applied here.
        timeout_override_secs: 8 * 60 * 60,
      });

      entry.lastExitCode = result.exitCode ?? null;

      const combinedOut = `${result.stderr || ""}\n${result.stdout || ""}`.trim();
      if (
        result.timedOut === true ||
        result.exitCode !== 0 ||
        result.stdout.includes("ChunkedEncodingError") ||
        result.stderr.includes("ChunkedEncodingError") ||
        result.stdout.includes("Exception") ||
        result.stderr.includes("Exception")
      ) {
        const tail = combinedOut.length > 6_000 ? `${combinedOut.slice(0, 6_000)}\n… [truncated]` : combinedOut;
        const toNote = result.timedOut
          ? "Timed out after 8h (CVE maintenance cap). For very large NVD pulls, run `main.py` in the integrated terminal, or raise **Settings → run_command timeout** for agent-driven runs. "
          : "";
        throw new Error(
          `CVE maintenance failed.\n` +
            toNote +
            `• cwd: ${env.workspaceRoot}\n` +
            `• command: bash -lc ${JSON.stringify(cmd)}\n` +
            `• exit: ${String(result.exitCode)}; timedOut: ${String(result.timedOut === true)}\n` +
            `---- output (stderr+stdout) ----\n` +
            (tail || "(no output)"),
        );
      }

      try {
        await invoke<string>("read_text_file", {
          path: `${env.workspaceRoot}/${recipe.artifactRelPath}`,
        });
        entry.artifacts.lastVerifiedExistence = true;
      } catch {
        entry.artifacts.lastVerifiedExistence = false;
        entry.currentStatus = "degraded";
        entry.lastErrorLog = "Run reported success but artifact read failed.";
      }

      if (entry.currentStatus !== "degraded") {
        entry.currentStatus = "idle";
      }
      if (entry.currentStatus === "idle") {
        entry.lastSuccessfulSync = isoFromMs(Date.now());
      }
      entry.nextScheduledSync = isoFromMs(Date.now() + recipe.intervalMs);
      recordRunMetrics(entry, performance.now() - t0, entry.currentStatus === "idle");
      try {
        await syncCtiVaultCvesToAppNow();
      } catch (vaultSyncErr) {
        console.warn("CVE maintenance: vault→app IOC sync failed:", vaultSyncErr);
      }
    } catch (e: unknown) {
      console.error("CVE Update Error:", e);
      const msg = e instanceof Error ? e.message : String(e);
      entry.lastErrorLog = msg;
      entry.currentStatus = "failed";
      entry.nextScheduledSync = isoFromMs(Date.now() + 60 * 60 * 1000);
      recordRunMetrics(entry, performance.now() - t0, false);
    }

    await this.saveState(state);
  }

  private static async runIOCsUpdate(state: MaintenanceStatus): Promise<void> {
    const recipe = PROJECT_RECIPES.find((r) => r.projectId === VISUAL_WORKSPACE_MAP.FEED_INGEST)!;
    const proj = recipe.projectId;
    const entry = state.projects[proj];
    entry.currentStatus = "running";
    entry.lastExitCode = null;
    entry.lastErrorLog = null;
    await this.saveState(state);

    const t0 = performance.now();
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      const baseline = await maxFileModifiedMsUnder(env.workspaceRoot, recipe.artifactRelPath);

      // Same pipeline as other maintenance jobs: headless `run_command` (not the PTY) so
      // "Update all datasets" / scheduled runs always start workers. `nohup` + background keeps
      // Celery alive after this bash process exits. PATH ensures project-local `celery` resolves.
      // `&` cannot be followed by `&&` — one shell line: `cd; export; nohup& nohup& true`
      const iocsCmd =
        `cd ${proj} && export PATH="$PWD/.venv/bin:$PATH" && ` +
        `nohup bash celery_worker.sh >>.bacongris_celery_worker.log 2>&1 & ` +
        `nohup bash celery_scheduler.sh >>.bacongris_celery_scheduler.log 2>&1 & ` +
        `true`;
      const startResult = await invoke<{
        exitCode: number | null;
        stdout: string;
        stderr: string;
        denied?: { reason: string; requested?: string };
      }>("run_command", {
        program: "bash",
        args: ["-c", iocsCmd],
        cwd: env.workspaceRoot,
      });
      entry.lastExitCode = startResult.exitCode ?? null;
      if (startResult.denied) {
        const r = startResult.denied;
        throw new Error(
          `IOCs: run_command denied for ${r.requested ?? "bash"}: ${r.reason}`,
        );
      }
      if (startResult.exitCode !== 0) {
        const o = `${startResult.stderr || ""}\n${startResult.stdout || ""}`.trim();
        throw new Error(
          `IOCs: could not start Celery scripts (exit ${String(startResult.exitCode)}).\n` +
            `• cwd: ${env.workspaceRoot}\n` +
            `• command: bash -lc ${JSON.stringify(iocsCmd)}\n` +
            `---- output ----\n${o || "(no output)"}`,
        );
      }

      await handshakeDelay();
      const after = await maxFileModifiedMsUnder(env.workspaceRoot, recipe.artifactRelPath);
      const rootPath = `${env.workspaceRoot}/${recipe.artifactRelPath}`;
      let rows: DirListRow[] = [];
      try {
        rows = await listDirAbs(rootPath);
      } catch {
        rows = [];
      }

      const stale = rows.length === 0 || after <= baseline;
      entry.artifacts.lastVerifiedExistence = !stale && rows.length > 0;
      if (stale) {
        entry.currentStatus = "stale";
        entry.lastErrorLog =
          `IOCs: after maintenance started Celery via \`run_command\` (nohup worker + scheduler), file mtimes under \`${recipe.artifactRelPath}/\` did not advance (baselineMs=${baseline}, afterMs=${after}). ` +
            `Celery may be failing, or \`.venv\` missing (create with \`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\`) — see \`.bacongris_celery_*.log\` in that folder.`;
        recordRunMetrics(entry, performance.now() - t0, false);
      } else {
        entry.currentStatus = "idle";
        entry.lastSuccessfulSync = isoFromMs(Date.now());
        recordRunMetrics(entry, performance.now() - t0, true);
      }
      entry.nextScheduledSync = isoFromMs(Date.now() + recipe.intervalMs);
    } catch (e: unknown) {
      console.error("IOCs Update Error:", e);
      entry.lastErrorLog = e instanceof Error ? e.message : String(e);
      entry.currentStatus = "failed";
      entry.nextScheduledSync = isoFromMs(Date.now() + 15 * 60 * 1000);
      recordRunMetrics(entry, performance.now() - t0, false);
    }

    await this.saveState(state);
  }

  private static async runASMUpdate(state: MaintenanceStatus): Promise<void> {
    const recipe = PROJECT_RECIPES.find((r) => r.projectId === VISUAL_WORKSPACE_MAP.RECON_ASM)!;
    const proj = recipe.projectId;
    const entry = state.projects[proj];
    entry.currentStatus = "running";
    entry.lastErrorLog = null;
    await this.saveState(state);

    const t0 = performance.now();
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      if (!env.dockerVersion) {
        throw new Error("Docker is not available on PATH (maintenance cannot run docker compose for ASM).");
      }

      const result = await invoke<{
        exitCode: number | null;
        stdout: string;
        stderr: string;
      }>("run_command", {
        program: "docker",
        args: ["compose", "up", "-d"],
        cwd: `${env.workspaceRoot}/${proj}`,
      });

      entry.lastExitCode = result.exitCode ?? null;

      const asmCwd = `${env.workspaceRoot}/${proj}`;
      const asmOut = `${result.stderr || ""}\n${result.stdout || ""}`.trim();
      if (result.exitCode !== 0) {
        const tail = asmOut.length > 4_000 ? `${asmOut.slice(0, 4_000)}\n… [truncated]` : asmOut;
        throw new Error(
          `ASM maintenance failed.\n• cwd: ${asmCwd}\n• command: docker compose up -d\n• exit: ${String(result.exitCode)}\n---- output ----\n${tail || "(no output)"}`,
        );
      }

      try {
        await invoke<string>("read_text_file", {
          path: `${env.workspaceRoot}/${recipe.artifactRelPath}`,
        });
        entry.artifacts.lastVerifiedExistence = true;
      } catch {
        entry.artifacts.lastVerifiedExistence = false;
        entry.currentStatus = "degraded";
        entry.lastErrorLog = "Docker compose exited 0 but README artifact missing.";
      }

      if (entry.currentStatus !== "degraded") {
        entry.currentStatus = "idle";
      }
      if (entry.currentStatus === "idle") {
        entry.lastSuccessfulSync = isoFromMs(Date.now());
      }
      entry.nextScheduledSync = isoFromMs(Date.now() + recipe.intervalMs);
      recordRunMetrics(entry, performance.now() - t0, entry.currentStatus === "idle");
    } catch (e: unknown) {
      console.error("ASM Update Error:", e);
      entry.lastErrorLog = e instanceof Error ? e.message : String(e);
      entry.currentStatus = "failed";
      entry.nextScheduledSync = isoFromMs(Date.now() + 60 * 60 * 1000);
      recordRunMetrics(entry, performance.now() - t0, false);
    }

    await this.saveState(state);
  }

  private static async runIntelxUpdate(state: MaintenanceStatus): Promise<void> {
    const recipe = PROJECT_RECIPES.find((r) => r.projectId === VISUAL_WORKSPACE_MAP.LEAKS_PII)!;
    const proj = recipe.projectId;
    const entry = state.projects[proj];
    entry.currentStatus = "running";
    entry.lastExitCode = null;
    entry.lastErrorLog = null;
    await this.saveState(state);

    const t0 = performance.now();
    try {
      const env = await invoke<EnvironmentInfo>("get_environment");
      const baseline = await maxFileModifiedMsUnder(env.workspaceRoot, recipe.artifactRelPath);

      await invoke("run_trusted_workflow", {
        workflow: "intelx",
        query: INTELX_MAINTENANCE_QUERY,
        intelx_start_date: null,
        intelx_end_date: null,
        intelx_search_limit: null,
        cve_start_date: null,
        cve_end_date: null,
        cve_cvss: null,
        cve_cvss_v4: null,
      });

      await handshakeDelay();

      const maxAfter = await maxFileModifiedMsUnder(env.workspaceRoot, recipe.artifactRelPath);
      const rootPath = `${env.workspaceRoot}/${recipe.artifactRelPath}`;
      let rows: DirListRow[] = [];
      try {
        rows = await listDirAbs(rootPath);
      } catch {
        rows = [];
      }

      const stale = intelxArtifactLooksStale({
        baselineMaxMtimeMs: baseline,
        rowsAtRoot: rows,
        maxMtimeAfterMs: maxAfter,
      });

      entry.artifacts.lastVerifiedExistence = !stale;
      if (stale) {
        entry.currentStatus = "stale";
        entry.lastErrorLog =
          "IntelX workflow dispatched but csv_output shows no fresh results (stale/incomplete).";
        recordRunMetrics(entry, performance.now() - t0, false);
      } else {
        entry.currentStatus = "idle";
        entry.lastSuccessfulSync = isoFromMs(Date.now());
        recordRunMetrics(entry, performance.now() - t0, true);
      }
      entry.nextScheduledSync = isoFromMs(Date.now() + recipe.intervalMs);
    } catch (e: unknown) {
      console.error("IntelX maintenance error:", e);
      entry.lastErrorLog = e instanceof Error ? e.message : String(e);
      entry.currentStatus = "failed";
      entry.nextScheduledSync = isoFromMs(Date.now() + 60 * 60 * 1000);
      recordRunMetrics(entry, performance.now() - t0, false);
    }

    await this.saveState(state);
  }
}
