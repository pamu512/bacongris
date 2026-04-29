/**
 * True when the user is asking for a **list / catalog** of workflows or projects, not to execute one.
 * Also used to **block** `run_trusted_workflow` in the agent loop (see `loop.ts`).
 */
export function isWorkflowCatalogQuestion(userText: string): boolean {
  const t = userText.trim();
  if (t.length < 4) return false;
  const lower = t.toLowerCase();
  if (/\b(run|start|execute|launch|begin)\b/.test(lower) && /\b(intelx|cve|cve_nvd|workflow_runner)\b/.test(lower)) {
    return false;
  }
  return (
    /\b(what|which|list|show|enumerate|tell me (about|what))\b.*\bworkflows?\b/.test(lower) ||
    /\bworkflows?\b.*\b(available|avilable|avaliable|availble|there|exists?|in (this|the) (repo|workspace)?)\b/.test(
      lower,
    ) ||
    /\b(available|avilable|avaliable|availble)\s+workflows?\b/.test(lower) ||
    /\b(available|list)\b.*\bworkflows?\b/.test(lower) ||
    /\bwhat (can|could) i (run|start|use|do here)\b/.test(lower) ||
    /^\s*list (the )?projects?\s*$/i.test(t.trim())
  );
}

/**
 * "What workflows are available?" / list projects — informational, not a request to start Intelx.
 */
export function getWorkflowCatalogInfoHint(userText: string): string | null {
  if (!isWorkflowCatalogQuestion(userText)) return null;

  return `## Host routing hint (this user turn only) — **workflow / project catalog (informational)**
The user is asking what **workflows or top-level projects** exist — **not** to start a run in this turn.

- **Do not** call **\`run_trusted_workflow\`**, open **Docker**, or **\`send_integrated_terminal\` workflow_runner** to answer. Starting **intelx** with **no** \`query\` only shows IntelX’s **interactive** “Enter a domain…” prompt in the bottom terminal — that **does not** list Bacongris workflows and wastes the user’s time.
- **Do** answer from: (1) the **Session workspace index** in the system message (if present), else one **\`analyze_workspace_run_requirements\`** default index; (2) **\`read_text_file\`** on **\`CTI_FUNCTION_MAP.md\`**, **\`SCRIPT_WORKFLOWS.md\`**, or **\`README.txt\`** at **workspaceRoot** / **\`scripts/\`** when they exist; (3) in prose, state that **\`run_trusted_workflow\`** only bundles **\`intelx\`** (→ Intelx_Crawler) and **\`cve\`** / **\`cve_nvd\`** (→ CVE_Project_NVD), and list other folders from the index in short bullets (e.g. ASM-fetch-main, Compromised_user_Mac) with their roles.`;
}

/**
 * Client-side nudge for common mis-routes (soft; model may still ignore).
 * See system prompt tables — this repeats the Intelx vs Brand Scout split for breach-style asks.
 */
export function getLeakExposureRoutingHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 3) return null;
  const lower = t.toLowerCase();
  const hasEmail = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(t);

  const strongLeak =
    /\b(leaks?|breach(?:es|ed)?|paste(?:s)?|dump(?:s)?|pwned|hibp|have i been|dehashed)\b/i.test(
      t,
    ) || /(check for leaks|data breach|breach check|leak check)/i.test(t);

  const intelxRun =
    (/\b(intelx|intel x|intelx-scraper)\b/i.test(t) && /\b(run|start|exec|up|compose|docker)\b/i.test(lower)) ||
    /^\s*run\s+intelx\s*$/i.test(t.trim());

  const emailPlusExposure =
    hasEmail &&
    /\b(leak|breach|paste|dump|expos|pwn|compromis|credenti|hibp|intelx)\b/i.test(lower);

  if (!strongLeak && !emailPlusExposure && !intelxRun) return null;

  return `## Host routing hint (this user turn only)
This message plausibly matches **EXPOSURE / LEAK** or **IntelX-style** work (not brand-only phishing UI).

- **Use \`Intelx_Crawler\`** for breach / paste / “is this email in a dump?”-style requests—**read that project’s README** and run the workflow it documents (terminal / compose as written there).
- If the README uses **Docker Compose**, the compose file is almost always under **\`Intelx_Crawler/\`** (not the bare workspace root). Use **\`send_integrated_terminal\`** with **\`cwd: "Intelx_Crawler"\`** (or \`cd Intelx_Crawler && docker compose ...\`) so you do not get *no configuration file provided: not found*.
- **Do not** default to **\`Phishing_and_Social_Media_All-in-one\` (Brand Scout)** for that intent: that tree is **BRAND / FRAUD** (per the capability map), not “email in a breach database.”
- If the user clearly asked for **phishing/brand** scanning (domains, permutations, brand impersonation) without a breach/leak ask, then Phishing/Brand is appropriate.`;
}

/**
 * Any time the user (or an error) touches Docker Compose—remind: compose file lives in a project subfolder.
 */
export function getDockerComposeWorkingDirHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 2) return null;
  const lower = t.toLowerCase();
  const match =
    /\b(docker\s+compose|docker-compose|compose\.ya?ml|compose\s+run|intelx-scraper)\b/i.test(
      t,
    ) ||
    /\bintelx\b/.test(lower) ||
    /no configuration file provided|not found.*compose/i.test(t);
  if (!match) return null;

  return `## Host routing hint — Docker Compose **working directory**
- \`docker compose\` loads \`compose.yaml\` / \`docker-compose.yml\` from the **current directory** (or from \`-f\`). Running from the monorepo **root** when the file is under a subfolder produces: *no configuration file provided: not found*.
- **Do this:** \`send_integrated_terminal\` with **\`cwd\`** = the project folder that contains the compose file (e.g. \`"Intelx_Crawler"\` relative to workspace), and **\`text\`** = \`docker compose run --rm -it <service>\\n\` per README. **Or** one line: \`cd Intelx_Crawler && docker compose run ...\\n\` (use the real folder + service names from that README).
- **List_directory** the project or **read_text_file** its README if the path is unclear.`;
}

/**
 * "run cve" / "CVE project" → **CVE_Project_NVD** (not Intelx_Crawler).
 */
export function getRunCveProjectHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 3) return null;
  const lower = t.toLowerCase();
  const cveNvd =
    /cve_?project_?nvd|cve_?nvd|nvd\s+project/.test(lower) ||
    /^\s*run\s+cve\s*$/i.test(t) ||
    /\b(run|start)\s+cve\b/.test(lower) ||
    (/\bcve\b/.test(lower) && /\b(run|start|exec|open)\b/.test(lower));
  if (!cveNvd) return null;

  return `## Host routing hint (this user turn only)
The user is asking to **run the local CVE / NVD project** in this workspace: **\`CVE_Project_NVD\`**. That is a **different folder** from \`Intelx_Crawler\` (IntelX / leak-style workflows).

- Use **\`read_text_file\` \`CVE_Project_NVD/README.md\`**, then **\`send_integrated_terminal\`** with \`text\` lines under that project (e.g. \`cd CVE_Project_NVD && python3 main.py\`), per the README. **Do not** start Intelx, Docker, or random \`echo\` “workspace verified” scripts unless the user named that project.`;
}

/**
 * NVD / CVE / vendor vulnerability questions → CVE_Project_NVD; also reminds tool shapes (text vs program).
 */
export function getCveVulnRoutingHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 8) return null;
  const vuln =
    /\b(vulnerabilit(?:y|ies)|CVE|NVD|cves?|zero-?day|patch(es)?|security (bulletin|advisory|update)|exploit(s)?)\b/i.test(
      t,
    );
  if (!vuln) return null;

  return `## Host routing hint (this user turn only)
This looks like a **vulnerability / CVE / NVD**-style question. Prefer **CVE_Project_NVD**: **read_text_file** its README, then **send_integrated_terminal** per that doc (often under \`CVE_Project_NVD/\` with \`cwd\` or \`cd\`).

- **\`send_integrated_terminal\`** takes **\`text\`** (full shell line(s)), not \`program\`+\`args\` like \`run_command\`.
- **\`run_command\`** needs an allowlisted binary—use **\`python3\`** with **\`["-m","pip",...]\`** instead of bare **\`pip\`** unless Settings lists \`pip\`.`;
}

/**
 * "Check the results" / "analyse the result" / "run analysis on findings" after a likely IntelX (or similar) run — use files, not a new index.
 */
export function getIntelxPostRunResultsHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 4) return null;
  const lower = t.toLowerCase();
  // "analysis" is not matched by "analy[sz]e" — include it explicitly; allow typo "finidings".
  const hasReviewVerb =
    /\b(check|analy[sz]e[ds]?|analy[sz]is|analy[sz]ing|analysis|review|interpret|what (did|happened)|summar(y|ise|ize)|explain|run\s+analysis|look\s+at|go\s+through|mine|dig(?:\s+into)?)\b/i.test(
      t,
    );
  const hasRunSubject =
    /\b(result|results|output|outcome|findings?|finidings?|it|search|run|that|this|the\s+data|file|files|csv|row|excerpt)\b/i.test(
      t,
    );
  const analysisOnFindings =
    /\b(findings?|finidings?)\b/i.test(t) &&
    /\b(analy[sz]e[ds]?|analy[sz]is|analy[sz]ing|analysis|review|summar|run\s+analysis)\b/i.test(
      t,
    );
  const runAnalysisOnPhrase = /\brun\s+analysis\s+on\b/i.test(lower);
  const veryShort =
    t.length < 50 &&
    /^(analy[sz]e|analy[sz]is|check|review|summar|what|show|read)\b/i.test(t);

  if (
    !(hasReviewVerb && hasRunSubject) &&
    !veryShort &&
    !analysisOnFindings &&
    !runAnalysisOnPhrase
  ) {
    return null;
  }
  if (!analysisOnFindings && !veryShort && !runAnalysisOnPhrase) {
    // Include `results` (plural); `\bresult\b` does **not** match the word "results"
    if (
      !/\b(result|results|output|outcome|findings?|finidings?|it|search|run|file|files|csv|data)\b/i.test(
        t,
      )
    ) {
      return null;
    }
  }

  return `## Host routing hint — Reviewing a script run (this user turn)
You do **not** get the **integrated terminal** log in the next model message. The user is asking to **read / summarize** something that already happened—not to **start** a new job.

- To answer after an **IntelX** search: **\`list_directory\` \`Intelx_Crawler/csv_output\`**, then the per-query subfolder (not a file named \`csv_output/results.csv\`—that path is usually **wrong**). The terminal may reference **\`final_report/…\`**, **\`filtered/…\`**, **\`Credential/…\`** under **\`Intelx_Crawler\`**; **\`list_directory\`** those dirs or **\`read_text_file\`** a path that exists. Use **\`read_text_file\`**, not **\`send_integrated_terminal\` \`cat\`** (stdout does not appear in chat).
- **Do not** call **\`run_trusted_workflow\` \`intelx\`** with **no \`query\`** to “analyze findings”—that opens the **interactive** IntelX prompt in the terminal and is the **wrong** tool. To re-search, call it with **\`query\`** set to the new seed. To **interpret** the last run, use \`list_directory\` + \`read_text_file\` only.
- **Do not** re-run the default \`analyze_workspace_run_requirements\` index for this, and do **not** switch to an unrelated project (Ransomware, etc.). The phrases **"analyse the results"** / **"analyze the results"** mean \`list_directory\` + \`read_text_file\` on IntelX paths — **never** the full-workspace index.
- If the last terminal run showed **0 records** / **no CSVs**, say so and suggest checking the **email spelling** (typos in the \`@\` local part are common) and re-running with **\`run_trusted_workflow\`** and a **corrected \`query\`**.
- If paths are missing, ask for a **paste** of the bottom terminal.`;
}
