import { invoke } from "@tauri-apps/api/core";

/** Merge `{workspaceRoot}/cti_vault.db` `cve_data` into the app `iocs` table (`ioc_type` = `cve`). */
export async function syncCtiVaultCvesToAppNow(): Promise<void> {
  await invoke("sync_cti_vault_cves_to_iocs", { limit: null });
}

/**
 * After `run_trusted_workflow` / terminal CVE runs, Python may still be writing the vault.
 * Immediate + delayed merges pick up data once commits land (WAL-visible).
 */
export function scheduleCveVaultSyncToAppDb(): void {
  const run = () => {
    void invoke("sync_cti_vault_cves_to_iocs", { limit: null }).catch(() => undefined);
  };
  run();
  window.setTimeout(run, 8_000);
  window.setTimeout(run, 45_000);
}
