/**
 * CTI agent routing: high-precision intent detection (catalog vs run, datasets, Docker, IntelX).
 * `isWorkflowCatalogQuestion` is also used to **block** `run_trusted_workflow` in `loop.ts`.
 */

// --- Shared regex building blocks ---
const WORKFLOW_IDS = [
  "intelx",
  "cve",
  "cve_nvd",
  "nvd",
  "workflow_runner",
  "ransomware",
  "asm_fetch",
  "asm",
  "social_mediav2",
  "social",
  "phishing_social",
  "phishing",
  "iocs_crawler",
  "iocs",
  "compromised_mac",
  "compromised",
].join("|");

const ACTION_VERBS = "run|start|execute|launch|begin";

/** True when the user wants a workflow/project **catalog**, not to execute a workflow this turn. */
export function isWorkflowCatalogQuestion(userText: string): boolean {
  const t = userText.trim();
  if (t.length < 4) return false;
  const lower = t.toLowerCase().replace(/\s+/g, " ");

  const runIntent = new RegExp(`\\b(${ACTION_VERBS})\\b.*\\b(${WORKFLOW_IDS})\\b`).test(lower);
  if (runIntent) return false;

  const catalogPatterns = [
    /\b(what|which|list|show|enumerate|tell me (about|what))\b.*\bworkflows?\b/,
    /\bworkflows?\b.*\b(available|exists?|repo|workspace|there|in (this|the) (repo|workspace)?)\b/,
    /\bworkflows?\b.*\b(avilable|avaliable|availble)\b/,
    /\b(avilable|avaliable|availble)\s+workflows?\b/,
    /\b(available|list)\b.*\bworkflows?\b/,
    /\bwhat (can|could) i (run|start|use|do|do here)\b/,
    /\bwhat\s+workflows?\b.*\b(can|could)\s+i\b/,
    /^\s*list (the )?projects?\s*$/i,
  ];

  return catalogPatterns.some((re) => re.test(lower));
}

/**
 * "What workflows are available?" / list projects — informational, not a request to start Intelx.
 */
export function getWorkflowCatalogInfoHint(userText: string): string | null {
  if (!isWorkflowCatalogQuestion(userText)) return null;

  return `## Routing hint — Workflow catalog (informational only)
The user is **browsing capabilities**, not asking you to execute a workflow this turn.

- **Strict block:** Do **not** call **\`run_trusted_workflow\`** for **\`intelx\`** without a **\`query\`** — it opens IntelX’s **interactive** prompt in the terminal and does **not** answer “what workflows exist.”
- **Do not** start **Docker** or **\`workflow_runner\`** just to list options.
- **Do** answer from: (1) the **Session workspace index** in the system message when present, else one default **\`analyze_workspace_run_requirements\`**; (2) **\`read_text_file\`** on **\`CTI_FUNCTION_MAP.md\`**, **\`SCRIPT_WORKFLOWS.md\`**, or **\`README.txt\`** / **\`scripts/\`** when they exist; (3) short prose: **\`intelx\`**, **\`cve\` / \`cve_nvd\`**, **\`iocs_crawler\`**, **\`ransomware\`**, **\`asm_fetch\`**, etc., matching **\`cti_workflows.json\`** and top-level folders from the index.`;
}

/**
 * "When was the last update?" / "update all datasets" — avoid fake container APIs; enforce workspace + real tools.
 */
export function getDatasetUpdateAndFreshnessHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 8) return null;
  const lower = t.toLowerCase().replace(/\s+/g, " ");

  const updateAll =
    (/\bupdate all\b/.test(lower) && /\b(dataset|data|feeds?|sources?|crawl|project)/.test(lower)) ||
    /^\s*update all the datasets\s*\.?\s*$/i.test(t) ||
    /\b(refresh|re-?sync|sync) all (the )?(data|dataset|feeds?|crawl)/.test(lower) ||
    /\b(run|start) (all|every) (crawl|feeds?|dataset|updates?)/.test(lower);

  const lastUpdate =
    /\b(when|what (time|date)|time|date)\b.*\b(last|previous|recent|stale|fresh)\b.*\b(update|sync|run|refresh)\b/.test(
      lower,
    ) ||
    /\b(when|time|date|stale|fresh|last)\b.*\b(update|sync|run|refresh)\b/.test(lower) ||
    /^\s*when was the last update\s*\.?\s*$/i.test(t) ||
    (/\b(last|stale|fresh|freshness)\b/.test(lower) &&
      /\b(update|sync|dataset|data|cve|nvd|intelx|feed|crawl)\b/.test(lower) &&
      !/\b(run|start|execute|launch)\s+(intelx|cve|iocs?)/.test(lower));

  if (!updateAll && !lastUpdate) return null;

  const topic =
    updateAll && lastUpdate
      ? "“last update” and refresh all"
      : updateAll
        ? "refresh / update all datasets"
        : "“last update” / recency only";

  const updateAllRunBlock = updateAll
    ? `

- **UI shortcut (user has the app open):** The **Maintenance** modal tracks **ASM, CVE, IOC, IntelX**. **“Update all datasets (maintenance)”** runs **ASM → CVE → IOC** only; **IntelX** is not in that one-click (use its own schedule, **\`run_trusted_workflow\`** with workflow **\`intelx\`**, a **\`query\`**, or the project README). Open **Maintenance** in the header for the one-click core refresh.
- **CRITICAL — “update all” is not a directory listing:** \`get_environment\` + \`list_directory\` **alone do not update anything.** After confirming projects exist, you must **start real work** in this session: **\`run_trusted_workflow\`** (one call per workflow id) and/or **\`send_integrated_terminal\`** / **\`run_command\`** per each project’s **\`README.md\`**. Stopping at env + list is **not** a completed request.
- **NEVER** use **\`write_text_file\`** to create or overwrite \`maintenance_status.json\` (or any \`*status*.json\` / sync ledger) with **invented** JSON or **hallucinated** ISO timestamps — that **fakes** a successful run and is **forbidden**. You cannot “record” an update you did not execute. To **read** live maintenance state in chat, use **\`system_maintenance_status\`** (or \`read_text_file\` on that path only if the file truly exists and you are not fabricating).
- **Flow:** (1) env + list (or \`system_maintenance_status\` to see current recency), (2) ask to approve if steps are heavy, (3) \`run_trusted_workflow\` for the first id (e.g. \`cve\` or \`iocs_crawler\`) **or** terminal line from README, then continue per project. IntelX often needs a **\`query\`**; CVE/NVD and CTI venv projects may be long-running — be explicit.`
    : "";

  return `## Host routing hint (this user turn) — **dataset ${topic}**
The user is asking about **recency of local data** or to **re-run** collectors. **Do not** use \`container.exec\` or any tool name not in the real tool list.

- **Workspace first:** call **\`get_environment\`**, then **\`list_directory\`** on \`.\` (or read **Session workspace index**). The **CTI monorepo** (folders like \`IOCs-crawler-main\`, \`CVE_Project_NVD\`, \`Intelx_Crawler\`, \`ASM-fetch-main\`, \`Ransomware_live_event_victim\`, …) must live under **\`workspaceRoot\`**. The app’s **default** empty workspace is only a stub — if those directories are **missing**, tell the user to open **Settings** and set **workspace** to the folder that **contains** those project dirs (e.g. their \`All_Scripts\` copy). **Never** \`cd IOCs-crawler-main\` or start Celery scripts until the folder is confirmed to exist under **\`workspaceRoot\`** (use \`list_directory\`).
- **“Last update” (informational):** the **\`system_maintenance_status\`** tool returns persisted per-project \`lastSuccessfulSync\` / \`currentStatus\` (when the app has run). The **“Local Intelligence is Stale”** banner refers to the **knowledge** snapshot in this chat, not a single global clock. If only **when** is asked, you can answer from that tool after a quick env check; **no** new runs are required.
- **“Update all” (mutating):** one **\`run_trusted_workflow\` per id** in order — \`intelx\` (needs **\`query\`** for non-interactive use), \`cve\` / \`cve_nvd\`, then each **\`cti_workflows.json\` id** (\`ransomware\`, \`asm_fetch\`, \`iocs_crawler\`, **…**). For Celery/IOCs-style projects, \`send_integrated_terminal\` with \`cwd\` = that folder and the exact \`celery\` / \`docker compose\` lines in its README. **Ask for approval** when steps start workers or long jobs.${updateAllRunBlock}`;
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
  const needsDocker =
    /\b(docker\s+compose|docker-compose|compose\.ya?ml|compose\s+run|intelx-scraper)\b/i.test(
      t,
    ) || /no configuration file provided|not found.*compose/i.test(t);
  if (!needsDocker) return null;

  return `## Host routing hint — Docker Compose **working directory**
- \`docker compose\` loads \`compose.yaml\` / \`docker-compose.yml\` from the **current directory** (or from \`-f\`). Running from the monorepo **root** when the file is under a subfolder produces: *no configuration file provided: not found*.
- **Do this:** \`send_integrated_terminal\` with **\`cwd\`** = the project folder that contains the compose file (e.g. \`"Intelx_Crawler"\` relative to workspace), and **\`text\`** = \`docker compose run --rm -it <service>\\n\` per README. **Or** one line: \`cd Intelx_Crawler && docker compose run ...\\n\` (use the real folder + service names from that README).
- **List_directory** the project or **read_text_file** its README if the path is unclear.`;
}

/**
 * "run cve" / "CVE project" → **CVE_Project_NVD** (not Intelx_Crawler).
 */
/**
 * "Run social media v2" / "run my project" — user names a **workspace top-level folder**, not an API function.
 */
export function getRunNamedProjectIntentHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 6) return null;
  const m = /^\s*(run|start|execute|launch)\s+(.+)$/i.exec(t);
  if (!m) return null;
  const rest = m[2]!.trim();
  if (rest.length < 2) return null;
  const r = rest.toLowerCase();
  if (r === "intelx" || r === "cve" || r === "nvd" || r === "cve nvd") return null;
  if (/^(the\s+)?(cti|bacongris|agent)\b/.test(r)) return null;
  if (/\b(what|which|how do i|workflows? available)\b/.test(t.toLowerCase())) {
    return null;
  }
  if (isWorkflowCatalogQuestion(t)) return null;

  return `## Host routing hint (this user turn) — **Run a user-named project (not a new API)**
The user is asking to **start** something they named in natural language (e.g. *social media v2*, a folder or script). **This is not a “missing” tool in the function list** — the **built-in** tools are generic (**read_text_file**, **list_directory**, **send_integrated_terminal**, **run_command**). Workspace app folders (IntelX, **Phishing** / **Social_MediaV2** / **Brand** trees, **CVE_Project_NVD**, etc.) are run via those tools.

- **Do not** say there is *no* function, or that only *threat* / *enrichment* APIs exist. **Do** match the name to a **top-level project folder** from the **Session workspace index** (or **\`list_directory\` \`.\`** / workspace root) — folder names in the index use **underscores**, not spaces: e.g. *Social Media V2* → \`Social_MediaV2\` or a listed **\`Phishing_and_…\`** / **\`...Social_Media...\`** name.
- **Read** that project’s **README** (\`read_text_file\` …) then **\`send_integrated_terminal\`**, with **\`cwd\`** = that folder, using the real entry point from the doc (\`python3\`, \`./scripts/venv_run.sh\`, \`docker compose\`, etc.). Use **\`run_command\`** only when the README is non-interactive and the user needs stdout in chat.
- The intent table: **phishing / brand / social (impersonation)** often maps to **\`Phishing_and_Social_Media_All-in-one\`** (or a similarly named top-level folder) **— not** a generic *“only VirusTotal/IOC”* list. If the name does not match any top-level folder, **\`list_directory\`** the workspace, pick the closest match, and state which folder you chose.`;
}

export function getRunCveProjectHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 3) return null;
  const lower = t.toLowerCase();
  const cveNvd =
    /cve_?project_?nvd|cve_?nvd|nvd\s+project/.test(lower) ||
    /^\s*run\s+cve\s*$/i.test(t) ||
    /\b(run|start)\s+cve\b/.test(lower) ||
    /\b(update|refresh|sync|pull|download)\s+(the\s+)?cve\b/.test(lower) ||
    /\b(update|refresh|sync)\s+(the\s+)?nvd\b/.test(lower) ||
    (/\bcve\b/.test(lower) && /\b(run|start|exec|open)\b/.test(lower));
  if (!cveNvd) return null;

  return `## Host routing hint (this user turn only)
The user is asking to **run or refresh the local CVE / NVD project** in this workspace: **\`CVE_Project_NVD\`**. That is a **different folder** from \`Intelx_Crawler\` (IntelX / leak-style workflows).

- Use **\`read_text_file\` \`CVE_Project_NVD/README.md\`** (never bare \`README.md\` at the workspace root), then **\`run_trusted_workflow\`** with \`workflow\` \`cve\` / \`cve_nvd\` **or** **\`send_integrated_terminal\`** with \`cwd\` / \`cd\` under that project per the README. When the run has populated **\`cti_vault.db\`**, call **\`sync_cti_vault_cves_to_iocs\`** so **\`ioc_search\`** (app SQLite) includes those CVEs. **Do not** start Intelx, Docker, or random \`echo\` “workspace verified” scripts unless the user named that project.`;
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

/**
 * User asks whether the agent can use the internet / web / online — clarify mediated tools.
 */
export function getExplicitWebAccessRoutingHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 6) return null;
  const lower = t.toLowerCase();
  const asks =
    /\b(do you|can you|are you able to)\b[\s\S]{0,80}\b(access|use|reach|browse|get on)\b[\s\S]{0,40}\b(the )?(internet|web|online)\b/.test(
      lower,
    ) ||
    /\b(internet access|web access|online access|access to the web|access the internet)\b/.test(
      lower,
    ) ||
    /\bcan you (search|look up|fetch)\b[\s\S]{0,20}\b(the )?web\b/.test(lower) ||
    /\b(have you got|do you have)\b[\s\S]{0,40}\b(internet|web access)\b/.test(lower);
  if (!asks) return null;

  return `## Host routing hint (this user turn) — **Web / internet / online**
The user is asking about **internet or web access** (or ability to use online resources).

- Answer clearly: you do **not** have a private browser or silent always-on internet—but the host allows **per-request, user-directed** outbound calls via real tools: **\`api_request\`** (HTTPS; **api_name** + **url** + **headers**; keys in Settings), **\`enrich_ioc\` / \`enrich_virustotal\` / \`enrich_shodan\` / \`enrich_otx\` / \`enrich_abusech\`**, **feeds** (\`add_feed\`, \`poll_feed\`, …), or **\`run_command\` / \`run_trusted_workflow\`** when a workspace README documents remote fetches.
- When they **explicitly** want live or “latest” public data, **use** those tools for this request—do **not** refuse with a blanket “no internet.” If URLs or API keys are missing, say what to configure in **Settings** or ask them to paste—never invent secrets.`;
}

/**
 * "Check the database" / "latest updates" in SQLite / recent IOCs — use ioc_search (last_seen DESC), not terminal-only.
 */
export function getLocalDatabaseLatestHint(userText: string): string | null {
  const t = userText.trim();
  if (t.length < 6) return null;
  const lower = t.toLowerCase().replace(/\s+/g, " ");

  const runCollectors =
    /\b(run|start|execute|launch|refresh|sync|re-?sync|pull|update)\b[\s\S]{0,80}\b(all\s+)?(dataset|feeds?|crawl|collector|workflow|maintenance\s+modal)\b/.test(
      lower,
    );
  if (runCollectors) return null;

  const hasDb =
    /\b(database|sqlite|\biocs?\b|cti_vault|vault\.db|\bthe\s+db\b|app\s+sqlite|local\s+sqlite)\b/.test(lower) ||
    /\b(iocs?\s+table|stored\s+iocs?)\b/.test(lower);
  const hasRecency =
    /\b(latest|recent|new(est)?|updates?|new\s+rows?|last\s+seen|recency|what'?s\s+new)\b/.test(lower);
  const hasBrowse =
    /\b(check|show|list|view|peek|inspect|query|see|how\s+many|pull\s+up|give\s+me|what\s+is|what\s+are)\b/.test(
      lower,
    );

  const iocRecencyBrowse =
    /\b(recent|latest|new(est)?)\b.*\b(iocs?|indicators?)\b/.test(lower) &&
    /\b(check|show|list|view|see|what|database|db|in\s+(the\s+)?app|stored|table)\b/.test(lower);

  if (!iocRecencyBrowse && !(hasDb && (hasRecency || hasBrowse))) return null;

  return `## Host routing hint (this user turn) — **Local IOC database / “latest updates”**
The user wants to **see what is stored** or **what changed recently** in the app’s **SQLite IOC store** (\`iocs\`), not necessarily to **run** a collector this turn.

- Call **\`ioc_search\`** with **\`limit\`** (e.g. **50**–**100**). Results are **ordered by \`last_seen\` descending** (newest first)—that is the default **“latest updates”** view.
- If they need **CVE rows from \`cti_vault.db\`** that are not in \`ioc_search\` yet: **\`sync_cti_vault_cves_to_iocs\`**, then **\`ioc_search\`** with **\`ioc_type\`** \`cve\`.
- For **per-job maintenance recency** (ASM/CVE/IOC/IntelX schedules), use **\`system_maintenance_status\`**. **Do not** treat this as a failed request if there was no **\`run_command\`** / terminal run—**\`ioc_search\`** is the correct read path.`;
}
