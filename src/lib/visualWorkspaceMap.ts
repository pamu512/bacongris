/**
 * Visual workspace authority: only primary on-disk top-level project folders
 * for CTI routing. Keep in sync with `scripts/cti_workflows.json` `relpath` values.
 */
export const VISUAL_WORKSPACE_MAP = {
  LEAKS_PII: "Intelx_Crawler",
  /** Relative to workspace root; maintenance watches this tree after IntelX runs. */
  LEAKS_PII_CSV_OUTPUT: "Intelx_Crawler/csv_output",
  VULNS_CVE: "CVE_Project_NVD",
  RECON_ASM: "ASM-fetch-main",
  RANSOMWARE: "Ransomware_live_event_victim",
  BRAND_PROTECTION: "Phishing_and_Social_Media_All-in-one",
  SOCIAL_INTEL: "Social_MediaV2",
  FEED_INGEST: "IOCs-crawler-main",
  FRAUD_MAC: "Compromised_user_Mac",
} as const;

export type VisualWorkspaceKey = keyof typeof VISUAL_WORKSPACE_MAP;

/** `run_trusted_workflow` venv+main.py rows (excludes IntelX Docker and CVE NVD, which are separate in the guide table). */
const VENV_GUIDE_KEY_ORDER: readonly Exclude<
  VisualWorkspaceKey,
  "LEAKS_PII" | "LEAKS_PII_CSV_OUTPUT" | "VULNS_CVE"
>[] = [
  "RANSOMWARE",
  "RECON_ASM",
  "SOCIAL_INTEL",
  "BRAND_PROTECTION",
  "FEED_INGEST",
  "FRAUD_MAC",
];

export function ctiVenvBundledRelPathsInGuideOrder(): string[] {
  return VENV_GUIDE_KEY_ORDER.map((k) => VISUAL_WORKSPACE_MAP[k]);
}
