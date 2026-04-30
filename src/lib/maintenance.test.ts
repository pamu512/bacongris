import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import { VISUAL_WORKSPACE_MAP } from "./visualWorkspaceMap";
import {
  isCveDatabaseStale,
  MaintenanceManager,
  parseMaintenanceStatusJson,
  intelxArtifactLooksStale,
  setFileHandshakeMsForTests,
  resetMaintenanceTestHooks,
  type MaintenanceStatus,
} from "./maintenance";
import * as Maint from "./maintenance";

const WS = "/tmp/bacongris-ws";

function envMock(): Record<string, unknown> {
  return {
    os: "darwin",
    arch: "arm64",
    family: "unix",
    homeDir: "/home",
    tempDir: "/tmp",
    cwd: WS,
    workspaceRoot: WS,
    scriptsDir: `${WS}/scripts`,
    workspaceIsCustom: false,
    python3Version: "Python 3.12",
    pythonVersion: null,
    dockerVersion: "Docker version 24.0.0, build de40ad0",
  };
}

describe("intelxArtifactLooksStale", () => {
  it("treats empty csv_output as stale", () => {
    expect(
      intelxArtifactLooksStale({
        baselineMaxMtimeMs: 0,
        rowsAtRoot: [],
        maxMtimeAfterMs: 0,
      }),
    ).toBe(true);
  });

  it("treats unchanged max mtime as stale", () => {
    expect(
      intelxArtifactLooksStale({
        baselineMaxMtimeMs: 1000,
        rowsAtRoot: [{ name: "sub", isDir: true }],
        maxMtimeAfterMs: 1000,
      }),
    ).toBe(true);
  });

  it("allows fresh output when tree has newer file mtimes", () => {
    expect(
      intelxArtifactLooksStale({
        baselineMaxMtimeMs: 1000,
        rowsAtRoot: [{ name: "sub", isDir: true }],
        maxMtimeAfterMs: 2000,
      }),
    ).toBe(false);
  });
});

describe("isCveDatabaseStale", () => {
  it("is true when there is no last sync", () => {
    expect(isCveDatabaseStale(null)).toBe(true);
  });

  it("is true when last sync is older than 12 hours", () => {
    const old = new Date(Date.now() - 13 * 60 * 60 * 1000).toISOString();
    expect(isCveDatabaseStale(old)).toBe(true);
  });

  it("is false when last sync is within 12 hours", () => {
    const recent = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    expect(isCveDatabaseStale(recent)).toBe(false);
  });
});

describe("parseMaintenanceStatusJson", () => {
  it("migrates legacy maintenance file to the new contract", () => {
    const raw = JSON.stringify({
      projects: {
        [VISUAL_WORKSPACE_MAP.VULNS_CVE]: {
          last_sync_timestamp: 1_700_000_000_000,
          success_rate: 80,
          next_scheduled_run: 1_700_000_000_000,
          status: "error",
          last_error: "boom",
        },
      },
    });
    const s = parseMaintenanceStatusJson(raw);
    expect(s.version).toBeTruthy();
    expect(s.projects[VISUAL_WORKSPACE_MAP.VULNS_CVE]?.lastErrorLog).toBe("boom");
    expect(s.projects[VISUAL_WORKSPACE_MAP.VULNS_CVE]?.currentStatus).toBe("failed");
    expect(s.projects[VISUAL_WORKSPACE_MAP.LEAKS_PII]).toBeDefined();
  });
});

describe("CVE maintenance run_command timeout", () => {
  afterEach(() => {
    resetMaintenanceTestHooks();
    vi.restoreAllMocks();
    vi.resetAllMocks();
  });

  it("passes timeout_override_secs (8h) to Tauri for the CVE/NVD bash pipeline", async () => {
    setFileHandshakeMsForTests(0);
    let diskState: MaintenanceStatus | null = null;
    const spy = vi.spyOn(Maint, "maxFileModifiedMsUnder");
    spy.mockResolvedValueOnce(100).mockResolvedValueOnce(10_000);

    const runCommandPayloads: unknown[] = [];
    vi.mocked(invoke).mockImplementation(
      async (cmd: string, args?: import("@tauri-apps/api/core").InvokeArgs) => {
        if (cmd === "get_environment") return envMock();
        if (cmd === "read_text_file") {
          const path = String((args as Record<string, unknown> | undefined)?.path ?? "");
          if (path.endsWith("maintenance_status.json")) {
            if (!diskState) {
              diskState = Maint.parseMaintenanceStatusJson("{}");
              diskState.globalLock = false;
            }
            return JSON.stringify(diskState);
          }
          if (path.endsWith("README.md")) return "# stub";
          return "";
        }
        if (cmd === "write_text_file") {
          diskState = Maint.parseMaintenanceStatusJson(
            String((args as Record<string, unknown> | undefined)?.content ?? "{}"),
          );
          return { ok: true };
        }
        if (cmd === "run_command") {
          runCommandPayloads.push(args);
          return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
        }
        if (cmd === "sync_cti_vault_cves_to_iocs") {
          return { ok: true, scanned: 0, inserted: 0, updated: 0, skipped: 0, vaultPath: "/tmp/x" };
        }
        if (cmd === "list_directory") {
          return [{ name: "x.txt", isDir: false, modifiedMs: 5000 }];
        }
        throw new Error(`unexpected invoke ${cmd}`);
      },
    );

    await Maint.MaintenanceManager.runAllMaintenanceJobsNow();

    const cvePayload = (runCommandPayloads as Record<string, unknown>[]).find(
      (p) => Array.isArray(p.args) && String((p.args as string[])[1] ?? "").includes("CVE_Project_NVD"),
    );
    expect(cvePayload?.timeout_override_secs).toBe(8 * 60 * 60);
    expect(cvePayload).not.toHaveProperty("timeoutOverrideSecs");
  });
});

describe("MaintenanceManager IntelX file handshake", () => {
  afterEach(() => {
    resetMaintenanceTestHooks();
    vi.resetAllMocks();
  });

  it("marks IntelX stale when workflow is dispatched but csv_output stays empty", async () => {
    setFileHandshakeMsForTests(0);
    let diskState: MaintenanceStatus | null = null;
    const intelxId = VISUAL_WORKSPACE_MAP.LEAKS_PII;
    const csvRel = VISUAL_WORKSPACE_MAP.LEAKS_PII_CSV_OUTPUT;

    vi.mocked(invoke).mockImplementation(
      async (cmd: string, args?: import("@tauri-apps/api/core").InvokeArgs) => {
        if (cmd === "get_environment") return envMock();
        if (cmd === "read_text_file") {
          const path = String((args as Record<string, unknown> | undefined)?.path ?? "");
          if (path.endsWith("maintenance_status.json")) {
            if (!diskState) {
              diskState = parseMaintenanceStatusJson("{}");
              const far = new Date("2099-01-01T00:00:00.000Z").toISOString();
              for (const k of Object.keys(diskState.projects)) {
                diskState.projects[k]!.nextScheduledSync = far;
              }
              diskState.projects[intelxId]!.nextScheduledSync = "2020-01-01T00:00:00.000Z";
            }
            return JSON.stringify(diskState);
          }
          if (path.endsWith("README.md")) return "# stub";
          return "";
        }
        if (cmd === "write_text_file") {
          diskState = parseMaintenanceStatusJson(
            String((args as Record<string, unknown> | undefined)?.content ?? "{}"),
          );
          return { ok: true };
        }
        if (cmd === "run_trusted_workflow") return {};
        if (cmd === "list_directory") {
          const path = String((args as Record<string, unknown> | undefined)?.path ?? "");
          if (path.endsWith(csvRel)) return [];
          return [{ name: "README.md", isDir: false, modifiedMs: 1 }];
        }
        if (cmd === "run_command") {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        if (cmd === "sync_cti_vault_cves_to_iocs") {
          return { ok: true, scanned: 0, inserted: 0, updated: 0, skipped: 0, vaultPath: "/tmp/x" };
        }
        if (cmd === "terminal_ensure_write") return {};
        throw new Error(`unexpected invoke ${cmd}`);
    },
    );

    await MaintenanceManager.runMaintenanceCycleNow();
    expect(diskState).not.toBeNull();
    expect(diskState!.projects[intelxId]?.currentStatus).toBe("stale");
  });
});
