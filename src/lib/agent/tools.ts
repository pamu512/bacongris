/**
 * Tool definitions for Ollama `/api/chat` (OpenAI-compatible function calling).
 */
export function getOllamaTools(): unknown[] {
  return [
    {
      type: "function",
      function: {
        name: "get_environment",
        description:
          "Return OS, arch, home, temp, process cwd, **workspaceRoot** / **scriptsDir** from Settings (same as the sidebar), and **python3Version** / **pythonVersion** strings from probing `python3 --version` and `python --version` on PATH (null if not found). Use these before recommending pip/venv/`python` runs: if both Python fields are null, tell the user to install Python 3 and fix PATH first. Never use `cwd` for file paths or run_command: that is the app process directory (e.g. src-tauri), not your workspace.",
        parameters: {
          type: "object",
          properties: {},
        },
      },
    },
    {
      type: "function",
      function: {
        name: "read_text_file",
        description:
          "Read a UTF-8 text file under the workspace or allowlisted roots. Path may be **relative to workspaceRoot** (e.g. CVE_Project_NVD/README.md) or absolute. **IntelX CSVs** are often `Intelx_Crawler/csv_output/<subfolder>/<file>.csv`—**list_directory** from `csv_output` and use the **exact** `name` in this field; do not retype long `...@_...` names from memory. If read fails, the error may name the real parent—**list_directory** that path next.",
        parameters: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description:
                "File path: relative to workspace root (forward slashes) or absolute under allowlisted roots",
            },
          },
          required: ["path"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "write_text_file",
        description:
          "Create or **replace** a **UTF-8** text file under allowlisted roots (usually **workspaceRoot**). Parent directories are created as needed. On overwrite, the previous file is **backed up** (same folder, with a .backup timestamp). Use to fix script/source after **run_command** shows errors, add small utilities, or append durable notes. Pass **content** (full new file text). For large binaries or non-text files, do not use this tool.",
        parameters: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description: "Absolute path to the file to write (must be under the workspace/allowlist)",
            },
            content: { type: "string", description: "Complete new file content (UTF-8). Empty string is allowed." },
          },
          required: ["path", "content"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "list_directory",
        description:
          "List files and folders in a directory (names + isDir only). Path may be relative to workspaceRoot or absolute under allowlisted roots.",
        parameters: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description:
                "Directory path: relative to workspace root or absolute under allowlisted roots",
            },
          },
          required: ["path"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "analyze_workspace_run_requirements",
        description:
          "Check run requirements. **Default (omit args):** fast **index** — one row per top-level project folder, manifests, excerpts. **Do not call this on every user message:** if the chat transcript **already** contains a successful result from this tool (workflowIndex / manifestFiles) for the current workspace, **skip** calling it again—reuse that output and go to read_text_file, then run steps via **send_integrated_terminal** (or run_command when capture-in-chat is needed). Call again only when: no prior index in the thread; user asks to rescan/refresh; you need **workflow_relative_path** to deep-scan **one** project; or **full_workspace: true** for a rare full-tree pass. **full_workspace: true** — deep scan entire tree (heavy). **workflow_relative_path** — deep scan that folder only (cached; use **use_cache: false** to force refresh).",
        parameters: {
          type: "object",
          properties: {
            workflow_relative_path: {
              type: "string",
              description:
                "Optional. Project folder under the workspace root, relative and forward-slash (e.g. \"Intelx_Crawler\" or \"Phishing_and_.../screenshots\"). Runs a **scoped** deep scan; omit for the fast index of all top-level projects.",
            },
            full_workspace: {
              type: "boolean",
              description:
                "If true, scan the full workspace at depth (expensive). Prefer false (default) for the index, or set workflow_relative_path to scope one project.",
            },
            use_cache: {
              type: "boolean",
              description:
                "For full and scoped deep scans, skip re-walking the tree if files did not change (default true). Set false to always rescan.",
            },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "run_trusted_workflow",
        description:
          "**Not** for *“what workflows are available?”* / *list workflows* / project **catalog** questions—answer those with the **Session workspace index**, **analyze_workspace_run_requirements** (if no index yet), and **read_text_file** on **CTI_FUNCTION_MAP.md** / **SCRIPT_WORKFLOWS.md** / README; **do not** start this tool just to list options. **Preferred for known CTI workflows** when the user wants to **start** a **new** run (not just read docs): runs Bacongris’ bundled **cross-platform** `workflow_runner.py` in the **integrated terminal** — it **preflights** (Docker / Python / folders) and starts the **documented** entrypoint. Workflows: **intelx** → `Intelx_Crawler` + Docker (default intelx-scraper). For **leak/breach checks** set **query**; the runner **pipes four stdin lines** (query, start/end dates, then **search limit** — default 2000 unless **intelx_search_limit**). **cve** / **cve_nvd** → `CVE_Project_NVD` + `main.py` (ignore **intelx_** fields). With **query** set, the runner pipes **six stdin lines**: **`search` → dates → vendors (query) → CVSS v3 → CVSS v4** (optional **cve_cvss** / **cve_cvss_v4**, else blank lines; **cve_start_date** / **cve_end_date** or wide defaults). Without **query**, the app runs the **interactive** menu. Use after you matched intent (leak/IntelX vs CVE/NVD). **Not** for “analyze the findings / summarize prior IntelX output in chat” — that is **list_directory** + **read_text_file** on `Intelx_Crawler/csv_output/`. **Do not** call with **intelx** and no **query** unless the user explicitly wants the **fully interactive** IntelX prompt. **Do not** use for arbitrary projects without a defined workflow — use **send_integrated_terminal** + README instead. On success, **commandSent** is the exact one-liner (absolute paths to `workflow_runner.py` and workspace). If the user runs the same thing in an external shell, they must copy **commandSent** or the real path — a literal `...` in a path is invalid. **preview** matches **commandSent**. IntelX JSON also has effective date/limit fields; the run may still be in progress. Output is only in the bottom terminal.",
        parameters: {
          type: "object",
          properties: {
            workflow: {
              type: "string",
              description:
                "intelx | cve | cve_nvd (cve and cve_nvd are the same: CVE_Project_NVD)",
            },
            query: {
              type: "string",
              description:
                "**IntelX:** email, domain, URL, or seeds — first piped line. **CVE / cve_nvd:** vendor / target sources (line before CVSS). Omit for fully interactive mode.",
            },
            intelx_start_date: {
              type: "string",
              description:
                "IntelX + query: start of date range YYYY-MM-DD (second piped line). Default in runner: 2000-01-01. Set when the user asked for a specific time window.",
            },
            intelx_end_date: {
              type: "string",
              description:
                "IntelX + query: end of date range YYYY-MM-DD (third piped line). Default: 2099-12-31.",
            },
            intelx_search_limit: {
              type: "string",
              description:
                "IntelX + query: fourth piped line — max results (e.g. 2000). Default: 2000.",
            },
            cve_start_date: {
              type: "string",
              description:
                "CVE + query: YYYY-MM-DD for main.py (second stdin line after `search`). Default: 2000-01-01.",
            },
            cve_end_date: {
              type: "string",
              description:
                "CVE + query: YYYY-MM-DD (third line). Default: 2099-12-31.",
            },
            cve_cvss: {
              type: "string",
              description:
                "CVE + query: fifth piped line — CVSS v3 threshold (e.g. >7.0) or leave empty for no threshold.",
            },
            cve_cvss_v4: {
              type: "string",
              description:
                "CVE + query: sixth piped line — CVSS v4 threshold line or empty for no threshold.",
            },
          },
          required: ["workflow"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "send_integrated_terminal",
        description:
          "**Default way to run project commands** in the **bottom** terminal. The host only runs this via **real API `tool_calls`**, with JSON `arguments` (e.g. `text` + optional `cwd`)—**do not** pretend to invoke it with a ` ```bash ` line. Creates a shell if none; if **text** has no line ending, one is **appended** so a one-liner **runs**. You may use multiple lines with real `\\n` or **cwd** to start in a project, or one `cd Project && cmd` from the workspace. **The assistant does not get shell stdout in chat**; use **read_text_file** / **list_directory** to read files — not `cat` or guessed `ls` (typos in long names break paths). If you need stdout in chat, use **run_command**; for interactive TTY, Docker, **pip**/**python3**/**docker compose** (add **-T** on `docker compose exec` when piping), use this. Prefer **run_trusted_workflow** for bundled **intelx** / **cve** when the user asked for that. Ask the user to **paste** errors if you need them.",
        parameters: {
          type: "object",
          properties: {
            text: {
              type: "string",
              description:
                "Bytes to send; a line ending is appended if missing. A trailing two-character backslash + n, or the four-char backslash + r + backslash + n, is turned into a real line ending (models sometimes send these instead of an actual newline).",
            },
            data: { type: "string", description: "Alias of text" },
            cwd: {
              type: "string",
              description: "If no terminal is running yet, start the shell in this allowlisted directory (defaults to workspace root)",
            },
          },
          required: [],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "run_command",
        description:
          "Run a program with **captured** stdout/stderr in the next **tool** message (headless, not the bottom terminal). Use an absolute path under an allowlisted root, or a **bare** name (e.g. `python3`) that matches an allowed executable. Bare `docker` / `docker-compose` resolve from standard install paths. **Prefer `send_integrated_terminal`** when the user should **see** the run. For `pip install`, use **program** `python3` and **args** `[\"-m\",\"pip\",\"install\",...]`. Tool results may include **denied** / **suggestedPath**; the user can approve in-app or add paths in Settings. If **program** is not allowlisted, the host returns a denial in the result JSON.",
        parameters: {
          type: "object",
          properties: {
            program: { type: "string" },
            args: {
              type: "array",
              items: { type: "string" },
              description: "Argv after program name (not run via shell). Alias: **arguments** (some models use that name).",
            },
            arguments: {
              type: "array",
              items: { type: "string" },
              description: "Same as **args** — use one or the other.",
            },
            cwd: {
              type: "string",
              description: "Working directory; must be allowlisted if set",
            },
          },
          required: ["program"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "run",
        description:
          "**Alias of `run_command` — identical parameters and behavior.** Use when the model or README naturally says “run” with `program` + `args` (captured stdout/stderr; allowlisted binaries; may include **denied** / **risk_assessment**). For interactive / Docker / menus, still use `send_integrated_terminal`.",
        parameters: {
          type: "object",
          properties: {
            program: { type: "string" },
            args: {
              type: "array",
              items: { type: "string" },
              description: "Argv after program name. Alias: **arguments**.",
            },
            arguments: {
              type: "array",
              items: { type: "string" },
              description: "Same as **args**.",
            },
            cwd: { type: "string", description: "Working directory; must be allowlisted if set" },
          },
          required: ["program"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_create",
        description:
          "Store or refresh an **IOC** in the app database (upsert on value + ioc_type + active profile). Use for IPs, domains, URLs, file hashes, emails. **profile_id** optional; defaults to the active workspace profile. **raw_json** optional metadata blob (truncated if huge).",
        parameters: {
          type: "object",
          properties: {
            value: { type: "string", description: "The indicator (e.g. 1.2.3.4, evil.com, hash)" },
            ioc_type: {
              type: "string",
              description: "Type: ipv4, ipv6, domain, url, email, md5, sha1, sha256, ssdeep, or other",
            },
            source: { type: "string", description: "Provenance (e.g. MISP, user, feed name)" },
            confidence: { type: "integer", description: "0-100, optional" },
            campaign_tag: { type: "string", description: "Optional campaign / case label" },
            raw_json: { type: "string", description: "Optional original JSON or notes" },
            profile_id: { type: "string", description: "Optional workspace profile id; default = active" },
            valid_until: {
              type: "integer",
              description: "Optional Unix time after which the row may be purged (maintenance)",
            },
            is_false_positive: { type: "boolean", description: "Mark as noise / irrelevant" },
            mitre_techniques: {
              type: "array",
              items: { type: "string" },
              description: "MITRE technique/tactic ids (T1059.001, TA0001, …)",
            },
          },
          required: ["value", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_search",
        description:
          "Query stored IOCs. By default only rows for the **active profile** or **global** (no profile) are returned. Set **all_profiles: true** to search all profiles. **include_false_positives: true** includes rows flagged as false positives. Filters are combined with AND.",
        parameters: {
          type: "object",
          properties: {
            value_contains: { type: "string", description: "Substring match on `value`" },
            ioc_type: { type: "string", description: "Exact type, e.g. sha256" },
            campaign: { type: "string", description: "Match campaign_tag (contains)" },
            source: { type: "string", description: "Match source (contains)" },
            profile_id: { type: "string", description: "Limit to this profile + global" },
            all_profiles: { type: "boolean", description: "If true, do not filter by profile" },
            include_false_positives: { type: "boolean", description: "If true, include false-positive rows" },
            limit: { type: "integer", description: "Max rows (default 100, cap 10000)" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_update",
        description: "Update an existing IOC row by **id** (from ioc_create / ioc_search). Only set fields you want to change.",
        parameters: {
          type: "object",
          properties: {
            id: { type: "string" },
            value: { type: "string" },
            ioc_type: { type: "string" },
            source: { type: "string" },
            confidence: { type: "integer" },
            campaign_tag: { type: "string" },
            first_seen: { type: "integer", description: "Unix seconds" },
            last_seen: { type: "integer", description: "Unix seconds" },
            raw_json: { type: "string" },
            valid_until: { type: "integer", description: "Unix time; use with clear_valid_until: false" },
            clear_valid_until: {
              type: "boolean",
              description: "If true, clears valid_until (no expiry)",
            },
            is_false_positive: { type: "boolean", description: "Re-tag as false positive" },
            mitre_techniques: {
              type: "array",
              items: { type: "string" },
              description: "Full replace of MITRE tags, or [ ] to clear",
            },
          },
          required: ["id"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_delete",
        description: "Delete a stored IOC by **id**.",
        parameters: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
          required: ["id"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_import_stix",
        description:
          "Parse a **STIX 2.x** JSON string (bundle or single object) and upsert extracted observables (IPs, domains, URLs, file hashes, etc.) into the IOC table.",
        parameters: {
          type: "object",
          properties: {
            json: { type: "string", description: "Full STIX JSON text" },
            source: { type: "string", description: "Default source label (default: stix)" },
            campaign_tag: { type: "string" },
            profile_id: { type: "string" },
          },
          required: ["json"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_export_stix",
        description:
          "Build a **STIX 2.1 bundle** JSON string from IOCs matching the same filters as **ioc_search** (for copy/paste, files, or downstream tools).",
        parameters: {
          type: "object",
          properties: {
            value_contains: { type: "string" },
            ioc_type: { type: "string" },
            campaign: { type: "string" },
            source: { type: "string" },
            profile_id: { type: "string" },
            all_profiles: { type: "boolean" },
            include_false_positives: { type: "boolean" },
            limit: { type: "integer" },
            producer_label: { type: "string", description: "Identity `name` in the bundle (default: Bacongris CTI)" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_maintenance",
        description:
          "Run IOC hygiene: delete rows past **valid_until**, cap confidence for stale last_seen, schedule grace expiry for very old rows. (Also runs on app start.)",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_import_misp",
        description:
          "Parse a **MISP** Event JSON export and upsert attributes (ip, domain, hash, url, etc.) into the IOC table.",
        parameters: {
          type: "object",
          properties: {
            json: { type: "string", description: "MISP Event JSON text" },
            source: { type: "string", description: "Default source label (default: misp)" },
            campaign_tag: { type: "string" },
            profile_id: { type: "string" },
          },
          required: ["json"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "api_request",
        description:
          "Call an external **HTTPS** API with the shared rate limiter and response cache. **api_name** (e.g. `virustotal`, `shodan`) must match a key in settings / `.api_keys.json` and drives quotas. You still pass **url** and **headers** (e.g. `x-apikey`) yourself. Returns JSON with **status**, **fromCache**, **body**.",
        parameters: {
          type: "object",
          properties: {
            url: { type: "string", description: "Full http(s) URL" },
            method: { type: "string", description: "GET, POST, …" },
            headers: { type: "object", description: "String map" },
            body: { type: "string" },
            api_name: { type: "string" },
            apiName: { type: "string", description: "Alias of api_name" },
          },
          required: ["url", "api_name"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "enrich_ioc",
        description:
          "Run **all configured** enrichers (VirusTotal, Shodan, abuse.ch, OTX) for this IOC, upsert it in the DB, and store `enrichment_results`. Requires matching API keys in settings.",
        parameters: {
          type: "object",
          properties: {
            ioc: { type: "string" },
            ioc_type: { type: "string" },
            profile_id: { type: "string" },
          },
          required: ["ioc", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "enrich_virustotal",
        description: "VirusTotal v3 for file hash, IP, or domain (key: `virustotal` or `vt`).",
        parameters: {
          type: "object",
          properties: {
            ioc: { type: "string" },
            ioc_type: { type: "string" },
            profile_id: { type: "string" },
          },
          required: ["ioc", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "enrich_shodan",
        description: "Shodan host/DNS (key: `shodan`).",
        parameters: {
          type: "object",
          properties: { ioc: { type: "string" }, ioc_type: { type: "string" }, profile_id: { type: "string" } },
          required: ["ioc", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "enrich_abusech",
        description: "MalwareBazaar (hash) or URLhaus (url).",
        parameters: {
          type: "object",
          properties: { ioc: { type: "string" }, ioc_type: { type: "string" }, profile_id: { type: "string" } },
          required: ["ioc", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "enrich_otx",
        description: "AlienVault OTX (key: `otx`).",
        parameters: {
          type: "object",
          properties: { ioc: { type: "string" }, ioc_type: { type: "string" }, profile_id: { type: "string" } },
          required: ["ioc", "ioc_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "add_feed",
        description:
          "Register a **feed** row. `ftype` = misp | otx | taxii2 | opencti; `url` = **base URL**; `api_key_ref` = key in **apiKeys**; **poll_interval_minutes** (optional) triggers automatic background polling. OpenCTI: e.g. `https://opencti.example` (no `/graphql` in url).",
        parameters: {
          type: "object",
          properties: {
            name: { type: "string" },
            ftype: { type: "string" },
            url: { type: "string" },
            api_key_ref: { type: "string" },
            poll_interval_minutes: { type: "integer" },
            filter_tags: { type: "string" },
          },
          required: ["name", "ftype"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "list_feeds",
        description: "List configured threat feeds.",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "get_feed_status",
        description: "Get one feed row by **id**.",
        parameters: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
      },
    },
    {
      type: "function",
      function: {
        name: "poll_feed",
        description:
          "Poll a feed by **feed_id** (or wait for the scheduled run): **MISP** `restSearch` (incremental **timestamp**), **OTX** pulses, **TAXII** STIX, **OpenCTI** GraphQL `stixCyberObservables` (paginated, up to 5k rows per run, `cursor_json` for resume).",
        parameters: { type: "object", properties: { feed_id: { type: "string" } }, required: ["feed_id"] },
      },
    },
    {
      type: "function",
      function: {
        name: "feed_search",
        description: "Search IOCs by **source** and optional value substring.",
        parameters: {
          type: "object",
          properties: { source: { type: "string" }, value_contains: { type: "string" }, limit: { type: "integer" } },
          required: ["source"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "feed_stats",
        description: "Aggregated IOC counts by source and `ioc_type`.",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "feed_health",
        description:
          "Per-feed health: last successful poll, last error, consecutive failures, stale vs. **poll_interval_minutes**, and **isUnhealthy** flags (HTTP/import failures are recorded; MISP uses incremental `timestamp` cursor in `cursor_json` after success).",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "source_reputation",
        description:
          "IOC counts and false-positive share by **source** (feeds, enricher names, or user) with a simple **reputationScore** (1.0 = no FPs in that bucket).",
        parameters: { type: "object", properties: {} },
      },
    },
    {
      type: "function",
      function: {
        name: "add_ioc_relationship",
        description: "Link two IOC **ids** with a `relationship_type` (e.g. resolves_to, same_as).",
        parameters: {
          type: "object",
          properties: {
            source_ioc: { type: "string" },
            target_ioc: { type: "string" },
            relationship_type: { type: "string" },
            source_data: { type: "string" },
            confidence: { type: "integer" },
          },
          required: ["source_ioc", "target_ioc", "relationship_type"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_pivot",
        description: "List **related** IOCs via stored relationships.",
        parameters: {
          type: "object",
          properties: { ioc_id: { type: "string" }, relationship_type: { type: "string" }, limit: { type: "integer" } },
          required: ["ioc_id"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "find_path",
        description: "Shortest path between two IOC **ids** in the relationship graph (undirected BFS).",
        parameters: {
          type: "object",
          properties: { from_ioc: { type: "string" }, to_ioc: { type: "string" }, max_depth: { type: "integer" } },
          required: ["from_ioc", "to_ioc"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "suggest_pivots",
        description:
          "Top ranked relationship pivots; each result includes a **rationale** string (relationship type + data source) for investigation context.",
        parameters: { type: "object", properties: { ioc_id: { type: "string" }, limit: { type: "integer" } }, required: ["ioc_id"] },
      },
    },
    {
      type: "function",
      function: {
        name: "campaign_analysis",
        description: "List IOCs whose **campaign_tag** matches.",
        parameters: { type: "object", properties: { campaign_tag: { type: "string" } }, required: ["campaign_tag"] },
      },
    },
    {
      type: "function",
      function: {
        name: "record_sighting",
        description: "Append a **sighting** for an `ioc_id` (temporal table).",
        parameters: { type: "object", properties: { ioc_id: { type: "string" }, source: { type: "string" }, context: { type: "string" } }, required: ["ioc_id"] },
      },
    },
    {
      type: "function",
      function: {
        name: "ioc_timeline",
        description: "Sighting rows for an IOC, newest first.",
        parameters: { type: "object", properties: { ioc_id: { type: "string" } }, required: ["ioc_id"] },
      },
    },
    {
      type: "function",
      function: {
        name: "campaign_track",
        description:
          "IOCs and **stats** for a **campaign** tag, plus optional **campaigns** table row; **recent_days** counts rows whose **first_seen** is in that window (default 7).",
        parameters: {
          type: "object",
          properties: {
            campaign_name: { type: "string" },
            recent_days: { type: "integer", description: "Window in days for newFirstSeenInLastNDays.count (default 7, max 365)" },
          },
          required: ["campaign_name"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "emerging_threats",
        description: "IOCs with **first_seen** in the last N **days** (default 7).",
        parameters: { type: "object", properties: { days: { type: "integer" } } },
      },
    },
    {
      type: "function",
      function: {
        name: "campaign_compare",
        description: "Set diff of `value` between two **campaign** tags.",
        parameters: { type: "object", properties: { campaign_a: { type: "string" }, campaign_b: { type: "string" } }, required: ["campaign_a", "campaign_b"] },
      },
    },
  ];
}
