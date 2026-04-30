import { Fragment, useCallback, useEffect, useState } from "react";
import {
  isAnyCtiMaintenanceStale,
  isCveDatabaseStale,
  MaintenanceManager,
  type MaintenanceStatus,
} from "./lib/maintenance";
import { VISUAL_WORKSPACE_MAP } from "./lib/visualWorkspaceMap";

/** Table order matches maintenance run order (run all: first three). */
const PROJECT_ROWS: { id: string; name: string }[] = [
  { id: VISUAL_WORKSPACE_MAP.RECON_ASM, name: "ASM Fetch" },
  { id: VISUAL_WORKSPACE_MAP.VULNS_CVE, name: "CVE / NVD" },
  { id: VISUAL_WORKSPACE_MAP.FEED_INGEST, name: "IOCs Crawler" },
  { id: VISUAL_WORKSPACE_MAP.LEAKS_PII, name: "IntelX" },
];

export function MaintenanceDashboard() {
  const [state, setState] = useState<MaintenanceStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [runAllBusy, setRunAllBusy] = useState(false);
  const [runAllErr, setRunAllErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      const s = await MaintenanceManager.getState();
      setState(s);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
    const interval = setInterval(() => void load(), 60_000);
    return () => clearInterval(interval);
  }, [load]);

  const anyStale = state && isAnyCtiMaintenanceStale(state);

  const onRunAll = useCallback(() => {
    if (runAllBusy) return;
    if (
      !window.confirm(
        "Run all dataset updates now? This runs in order: ASM (Docker compose), CVE/NVD, then IOCs (Celery). IntelX is not included here — it runs on its own schedule. This can take a long time and may start Docker or background workers. Continue?",
      )
    ) {
      return;
    }
    setRunAllErr(null);
    setRunAllBusy(true);
    void (async () => {
      try {
        await MaintenanceManager.runAllMaintenanceJobsNow();
        await load();
      } catch (e) {
        setRunAllErr(e instanceof Error ? e.message : String(e));
      } finally {
        setRunAllBusy(false);
      }
    })();
  }, [load, runAllBusy]);

  if (!state) {
    return (
      <div className="maintenance-dashboard">
        {loadError ? (
          <p className="maintenance-load-err" role="alert">
            {loadError}
          </p>
        ) : (
          <p className="muted">Loading maintenance state…</p>
        )}
      </div>
    );
  }

  return (
    <div className="maintenance-dashboard">
      <div className="maintenance-dashboard-toolbar">
        {anyStale && (
          <p className="maintenance-stale-banner" role="status">
            At least one dataset looks stale or failed — use a one-click run instead of the chat
            agent for bulk refresh.
          </p>
        )}
        <div className="maintenance-toolbar-buttons">
          <button
            type="button"
            className={`btn small${anyStale ? " primary" : ""}`}
            disabled={runAllBusy}
            onClick={onRunAll}
            title="Runs ASM, CVE, and IOC maintenance in sequence (ignores schedule; IntelX excluded)"
          >
            {runAllBusy
              ? "Running maintenance…"
              : anyStale
                ? "Update all datasets (maintenance)"
                : "Run all maintenance now"}
          </button>
          <button
            type="button"
            className="btn small ghost"
            onClick={() => void load()}
            disabled={runAllBusy}
          >
            Refresh
          </button>
        </div>
        {runAllErr && (
          <p className="maintenance-runall-err" role="alert">
            {runAllErr}
          </p>
        )}
      </div>
      {state.globalLock && (
        <p className="maintenance-global-lock" role="status">
          Global maintenance lock is set in <code>maintenance_status.json</code> — a run may be in
          progress, or a previous run left a stuck lock. <strong>Update all datasets</strong> clears
          a stuck lock automatically and starts a new run; if a run is already active in this
          window, wait for it to finish.
        </p>
      )}
      <div className="maintenance-table-wrap">
        <table className="maintenance-table">
          <thead>
            <tr>
              <th>Project</th>
              <th>Status</th>
              <th>Last sync</th>
              <th>Next run</th>
              <th>Artifact</th>
              <th>Runs / failures</th>
            </tr>
          </thead>
          <tbody>
            {PROJECT_ROWS.map((p) => {
              const s = state.projects[p.id];
              if (!s) {
                return (
                  <tr key={p.id} className="maintenance-row-missing">
                    <td colSpan={6}>
                      {p.name} (no state row)
                    </td>
                  </tr>
                );
              }

              const cveStale =
                p.id === VISUAL_WORKSPACE_MAP.VULNS_CVE &&
                isCveDatabaseStale(s.lastSuccessfulSync);
              const healthClass =
                s.currentStatus === "failed"
                  ? "health-error"
                  : s.currentStatus === "stale" || s.currentStatus === "degraded"
                    ? "health-warning"
                    : "health-ok";

              return (
                <Fragment key={p.id}>
                  <tr
                    className={
                      cveStale ? `maintenance-row-cve-stale ${healthClass}` : healthClass
                    }
                    title={
                      cveStale
                        ? "CVE / NVD local data: last success older than 12 hours"
                        : undefined
                    }
                  >
                    <td>
                      {p.name}
                      {cveStale && (
                        <span className="maintenance-cve-pill" title="CVE data &gt; 12h">
                          Stale
                        </span>
                      )}
                    </td>
                    <td>
                      {s.currentStatus}
                      {cveStale && s.currentStatus === "idle" && (
                        <span className="maintenance-subhint"> (DB &gt;12h)</span>
                      )}
                    </td>
                    <td>
                      {s.lastSuccessfulSync
                        ? new Date(s.lastSuccessfulSync).toLocaleString()
                        : "Never"}
                    </td>
                    <td>{new Date(s.nextScheduledSync).toLocaleString()}</td>
                    <td>
                      {s.artifacts.lastVerifiedExistence ? "OK" : "Unverified"}
                      <div
                        className="artifact-path"
                        title={s.artifacts.expectedOutputFile}
                      >
                        {s.artifacts.expectedOutputFile}
                      </div>
                    </td>
                    <td>
                      {s.metrics.totalRuns} / {s.metrics.failureCount}
                      {s.lastExitCode != null && (
                        <span className="exit-code" title="Last exit code">
                          {" "}
                          (exit {s.lastExitCode})
                        </span>
                      )}
                    </td>
                  </tr>
                  {s.lastErrorLog && (
                    <tr className="maintenance-error-trace-row">
                      <td colSpan={6}>
                        <details
                          className="maintenance-error-details"
                          open={s.currentStatus === "failed"}
                        >
                          <summary>Last error / trace ({p.name})</summary>
                          <pre className="maintenance-error-pre">{s.lastErrorLog}</pre>
                        </details>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
