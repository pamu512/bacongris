import {
  ctiVenvBundledRelPathsInGuideOrder,
  VISUAL_WORKSPACE_MAP,
} from "./lib/visualWorkspaceMap";

const CTI_VENV_BUNDLED_PATHS = ctiVenvBundledRelPathsInGuideOrder();

type Props = {
  onDismiss: (dontShowAgain: boolean) => void;
};

/**
 * First-run (or “Workflows help”): monorepo layout, `run_trusted_workflow` targets from
 * `scripts/workflow_runner.py` + `cti_workflows.json` (must match Tauri).
 */
export function WorkflowsGuideModal({ onDismiss }: Props) {
  return (
    <div
      className="import-backdrop workflows-guide-backdrop"
      role="presentation"
      onClick={() => onDismiss(false)}
    >
      <div
        className="import-modal workflows-guide-modal"
        role="dialog"
        aria-label="Workspace workflows guide"
        onClick={(e) => e.stopPropagation()}
      >
        <h3>Running workflows in your workspace</h3>
        <p className="workflows-guide-lead">
          Set the app <strong>workspace / profile</strong> to your CTI monorepo root (often named
          <code> All_Scripts</code>). The integrated terminal and agent commands run with that
          directory as the workspace root. Below: the <strong>usual top-level project folders</strong>{" "}
          in that repo, which ones are wired to <code>run_trusted_workflow</code>, and what
          parameters actually produce a good run.
        </p>

        <section className="workflows-guide-section">
          <h4>Typical monorepo layout (top-level folders)</h4>
          <p className="workflows-guide-muted">
            These names match a standard <code>All_Scripts</code>-style tree. Your disk layout may
            vary; if a folder is missing, skip it. The rows below (except the repo root) are{" "}
            <strong>bundled with the app runner</strong> — <code>run_trusted_workflow</code> uses{" "}
            <code>workflow_runner.py</code> plus <code>cti_workflows.json</code> (CTI venv) or
            built-in <code>intelx</code> / <code>cve_nvd</code>. You do <strong>not</strong> need a
            separate “second” workflow name: each folder has a <code>workflow</code> id in that
            manifest. If your clone uses a different entry file or no stdin, see the section
            <em>When your tree differs from the manifest</em> below.
          </p>
          <ul className="workflows-guide-list workflows-guide-tightlist">
            <li>
              <code>All_Scripts</code> — <strong>repository root</strong> you open as the
              workspace (not a subfolder).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.RANSOMWARE}</code> — <strong>bundled</strong> as workflow{" "}
              <code>ransomware</code> (ransomware / victim event tooling; venv +{" "}
              <code>main.py</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.RECON_ASM}</code> — <strong>bundled</strong> as{" "}
              <code>asm_fetch</code> (attack-surface / fetch; aliases e.g. <code>asm</code> in{" "}
              <code>cti_workflows.json</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.SOCIAL_INTEL}</code> — <strong>bundled</strong> as{" "}
              <code>social_mediav2</code> (social collection / analysis; aliases e.g.{" "}
              <code>social</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.BRAND_PROTECTION}</code> — <strong>bundled</strong> as{" "}
              <code>phishing_social</code> (phishing + social OSINT; aliases e.g.{" "}
              <code>phishing</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.FEED_INGEST}</code> — <strong>bundled</strong> as{" "}
              <code>iocs_crawler</code> (IOC crawling; alias <code>iocs</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.FRAUD_MAC}</code> — <strong>bundled</strong> as{" "}
              <code>compromised_mac</code> (compromised-Mac / endpoint flows; aliases e.g.{" "}
              <code>compromised</code>).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.LEAKS_PII}</code> — <strong>bundled</strong> as{" "}
              <code>intelx</code> (Docker; see table below).
            </li>
            <li>
              <code>{VISUAL_WORKSPACE_MAP.VULNS_CVE}</code> — <strong>bundled</strong> as{" "}
              <code>cve</code> / <code>cve_nvd</code> (NVD-specific <code>main.py</code> flow; see
              table).
            </li>
          </ul>
        </section>

        <section className="workflows-guide-section">
          <h4>Before any run (all projects)</h4>
          <ul className="workflows-guide-list">
            <li>
              <strong>Ollama</strong> in Settings, with a <strong>tool-capable</strong> model when
              you use the agent.
            </li>
            <li>
              <strong>Python 3</strong> on <code>PATH</code> — the bundled runner shells out to{" "}
              <code>python3</code> (or <code>python</code> on some setups) to run{" "}
              <code>workflow_runner.py</code>.
            </li>
            <li>
              <strong>Prepare folders</strong> in the sidebar if <code>scripts/</code> or the tree
              is missing; <strong>Scan run requirements</strong> (or{" "}
              <code>analyze_workspace_run_requirements</code>) surfaces install hints.
            </li>
            <li>
              The <strong>bottom terminal</strong> shows live output. The model does <strong>not</strong>{" "}
              receive that log automatically—use <code>read_text_file</code> / <code>list_directory</code>{" "}
              on outputs, or paste errors.
            </li>
          </ul>
        </section>

        <section className="workflows-guide-section">
          <h4>
            Bundled only — <code>run_trusted_workflow</code> / <code>workflow_runner.py</code>
          </h4>
          <p className="workflows-guide-muted">
            The app ships <code>workflow_runner.py</code> + <code>cti_workflows.json</code>.{" "}
            <strong>Workflow</strong> IDs: <code>intelx</code>, <code>cve</code> /{" "}
            <code>cve_nvd</code>, and the CTI venv rows below. The Python side resolves short aliases
            (e.g. <code>asm</code> → <code>asm_fetch</code>) as in the JSON.
          </p>
          <div className="workflows-guide-table-wrap">
            <table className="workflows-guide-table">
              <thead>
                <tr>
                  <th>Workflow ID</th>
                  <th>Folder &amp; stack</th>
                  <th>Parameters &amp; success tips</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <code>intelx</code>
                  </td>
                  <td>
                    <code>Intelx_Crawler</code> — <code>docker compose</code>, service{" "}
                    <code>intelx-scraper</code> (override: env <code>INTELX_COMPOSE_SERVICE</code>).
                  </td>
                  <td>
                    <strong>With <code>query</code> (non-empty):</strong> one line—email, domain,
                    URL, or search seed. Runner pipes <strong>four</strong> stdin lines to the
                    service: (1) query, (2) start date, (3) end date, (4) search limit. Map from the
                    tool/CLI: <strong>intelx_start_date</strong>, <strong>intelx_end_date</strong> —{" "}
                    <code>YYYY-MM-DD</code>; <strong>intelx_search_limit</strong> — e.g.{" "}
                    <code>2000</code>. Defaults if omitted: <code>2000-01-01</code>,{" "}
                    <code>2099-12-31</code>, <code>2000</code> (also via{" "}
                    <code>INTELX_START_DATE</code> / <code>INTELX_END_DATE</code> /{" "}
                    <code>INTELX_SEARCH_LIMIT</code>).
                    <br />
                    <strong>With no <code>query</code>:</strong> starts{" "}
                    <code>docker compose run --rm -it &lt;service&gt;</code> (interactive TTY)—only
                    when you <em>want</em> the in-container menu.
                    <br />
                    <strong>Hard limit:</strong> <code>query</code> max 2048 characters, single
                    line.
                  </td>
                </tr>
                <tr>
                  <td>
                    <code>cve</code>
                    <br />
                    <code>cve_nvd</code>
                  </td>
                  <td>
                    <code>CVE_Project_NVD</code> — runs <code>main.py</code> with a per-project{" "}
                    <code>.venv</code> and <code>pip install -r requirements.txt</code> unless
                    skipped.
                  </td>
                  <td>
                    <strong>With <code>query</code> (non-empty):</strong> the runner pipes stdin to{" "}
                    <code>main.py</code> in this <strong>order</strong> (per runner): line{" "}
                    <code>search</code> → <strong>cve_start_date</strong> → <strong>cve_end_date</strong>{" "}
                    → <strong>query</strong> (vendors / targets) → <strong>cve_cvss</strong> (v3) →{" "}
                    <strong>cve_cvss_v4</strong>. Dates default to <code>2000-01-01</code> …{" "}
                    <code>2099-12-31</code> if not set. CVSS fields can be blank for &quot;no
                    threshold&quot;. Env fallbacks: <code>CVE_SEARCH_START_DATE</code>,{" "}
                    <code>CVE_SEARCH_END_DATE</code>, <code>CVE_SEARCH_CVSS</code>,{" "}
                    <code>CVE_SEARCH_CVSS_V4</code>. Set <code>CVE_NVD_SKIP_PIP=1</code> (or tool
                    equivalent) to skip venv/pip (advanced; may break if deps missing).
                    <br />
                    <strong>With no <code>query</code>:</strong> runs <code>main.py</code>{" "}
                    interactively—use when you want the menu.
                    <br />
                    <strong>Constraints:</strong> <code>query</code> and each CVSS field must be a{" "}
                    <strong>single line</strong> (no newlines).
                  </td>
                </tr>
                <tr>
                  <td>
                    <code>ransomware</code>
                    <br />
                    <code>asm_fetch</code>
                    <br />
                    <code>social_mediav2</code>
                    <br />
                    <code>phishing_social</code>
                    <br />
                    <code>iocs_crawler</code>
                    <br />
                    <code>compromised_mac</code>
                  </td>
                  <td>
                    {CTI_VENV_BUNDLED_PATHS.map((path, i) => (
                      <span key={path}>
                        {i > 0 ? ", " : null}
                        <code>{path}</code>
                      </span>
                    ))}{" "}
                    — each uses a per-project <code>.venv</code>,{" "}
                    <code>pip install -r requirements.txt</code>, and the configured{" "}
                    <code>entry</code> (default <code>main.py</code> in the JSON).
                  </td>
                  <td>
                    <strong>With <code>query</code> (non-empty):</strong> the full string (up to ~16k
                    chars, <strong>multiline</strong> allowed) is piped as <strong>UTF-8 stdin</strong>{" "}
                    to the entry script—use this for the user’s search terms, multiline options, or
                    anything the app should feed without TTY. Map from the agent tool as{" "}
                    <code>query</code> only; no extra date/CVSS fields.
                    <br />
                    <strong>With no <code>query</code>:</strong> runs the entry script{" "}
                    <strong>interactively</strong> in the integrated terminal (TTY menus / prompts).
                    <br />
                    <strong>Tip:</strong> if the project does not read stdin, read its{" "}
                    <code>README</code> and use <code>send_integrated_terminal</code> or change{" "}
                    <code>entry</code> in <code>cti_workflows.json</code>.{" "}
                    <code>CVE_NVD_SKIP_PIP=1</code> or <code>--skip-pip-install</code> skips venv/pip
                    (same as CVE project).
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="workflows-guide-section">
          <h4>Chat shortcuts (app handles these without the model)</h4>
          <p>
            With <strong>no</strong> attachments, the app matches short <code>run</code> /{" "}
            <code>start</code> lines: <code>run intelx</code> / <code>run cve</code> (and{" "}
            <code>nvd</code> / <code>start</code> variants) for interactive mode, and forms like{" "}
            <code>run intelx for user@domain.com</code> or{" "}
            <code>run intelx user@domain.com</code> so the seed is passed as <code>query</code> (no Ollama). For anything else, use
            the agent and <code>run_trusted_workflow</code>. Watch the <strong>bottom</strong>{" "}
            terminal.
          </p>
        </section>

        <section className="workflows-guide-section">
          <h4>When your tree differs from the bundled manifest</h4>
          <p>
            The six CTI folders above are <strong>still</strong> bundled: they are listed in{" "}
            <code>cti_workflows.json</code> and started with the same{" "}
            <code>run_trusted_workflow</code> workflow ids. Use this section only if{" "}
            <strong>your</strong> copy of a project uses a different <code>entry</code> than{" "}
            <code>main.py</code>, or expects <strong>CLI</strong> flags instead of piped{" "}
            <code>query</code> — then edit <code>cti_workflows.json</code> (in app resources, or
            via <code>WORKFLOW_CTI_MANIFEST</code>), or run the README command with{" "}
            <code>send_integrated_terminal</code> / <code>run</code>. Use <code>run</code> /{" "}
            <code>run_command</code> when the model must <strong>see</strong> captured stdout in
            chat.
          </p>
        </section>

        <section className="workflows-guide-section">
          <h4>Where to look for outputs (bundled runs)</h4>
          <p>
            <strong>IntelX:</strong> CSV-style artifacts are commonly under{" "}
            <code>
              {VISUAL_WORKSPACE_MAP.LEAKS_PII}/csv_output/…
            </code>{" "}
            (confirm in that project’s README). <strong>CVE/NVD:</strong> check{" "}
            <code>{VISUAL_WORKSPACE_MAP.VULNS_CVE}</code> and whatever paths <code>main.py</code>{" "}
            documents. For CTI venv projects, check each project folder for
            outputs. Always verify with <code>list_directory</code> after a run; do not guess
            paths from memory.
          </p>
        </section>

        <div className="workflows-guide-actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => onDismiss(true)}
          >
            Got it, don’t show again
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onDismiss(false)}
          >
            Close
          </button>
        </div>
        <p className="workflows-guide-foot">
          Reopen anytime from the top bar: <strong>Workflows help</strong>.
        </p>
      </div>
    </div>
  );
}
