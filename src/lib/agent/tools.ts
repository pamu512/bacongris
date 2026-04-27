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
          "Return OS, arch, home, temp, process cwd, and **workspaceRoot** / **scriptsDir** from Settings (the allowlisted CTI workspace — same as the sidebar). Never use `cwd` for file paths or run_command: that is the app process directory (e.g. src-tauri), not your workspace.",
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
          "Read a UTF-8 text file. Path must be under user-configured allowlisted directories.",
        parameters: {
          type: "object",
          properties: {
            path: { type: "string", description: "Absolute or canonical file path" },
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
          "List files and folders in a directory under allowlisted roots (names + isDir only).",
        parameters: {
          type: "object",
          properties: {
            path: { type: "string", description: "Directory path under allowlisted roots" },
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
          "Check run requirements. **Default (omit args):** fast **index** — one row per top-level project folder (each subfolder = one workflow), with key manifests and short excerpts; workspace root can change, paths are relative. **full_workspace: true** (or mode \"full\") — deep scan of the entire tree (heavier; use sidebar or when you need every file). **workflow_relative_path** (e.g. \"CVE_Project_NVD\" or a nested subfolder) — deep scan of that directory only, with caching so unchanged projects are not re-scanned. Set **use_cache: false** (or no_cache) to force refresh.",
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
        name: "run_command",
        description:
          "Run a local program with arguments (no shell). Use an absolute path to the binary/script under an allowlisted directory, OR a bare name like python3/node that matches the *filename* of an entry in Settings → Allowed executables (e.g. allowed list contains /usr/bin/python3 → program can be python3). Bare `docker` (and legacy `docker-compose`) also resolve from standard install paths on macOS/Linux (Homebrew / Docker Desktop) without listing them. cwd must be under the workspace or another allowlisted root. Prefer this for non-interactive steps (including docker compose build and docker compose up -d). Long-running attached compose may hit the execution timeout — use up -d or the in-app Terminal. If the program is not allowlisted, the result includes **denied** and **suggestedPath**; the user can approve in the app (allow once) or add the path in Settings, then the agent can continue.",
        parameters: {
          type: "object",
          properties: {
            program: { type: "string" },
            args: {
              type: "array",
              items: { type: "string" },
              description: "Arguments (not run via shell)",
            },
            cwd: {
              type: "string",
              description: "Working directory; must be allowlisted if set",
            },
          },
          required: ["program", "args"],
        },
      },
    },
    {
      type: "function",
      function: {
        name: "send_integrated_terminal",
        description:
          "Type text into the in-app **integrated terminal** (bottom panel), like a user pasting. Creates a shell session if none exists, using **cwd** (optional) or the configured workspace. If **text** does not end in a line ending, one is **appended automatically** so a one-line command runs without the user pressing Enter. Output streams to the panel; this tool only confirms it was sent. For runs where you need stdout/stderr in the tool result, prefer **run_command**; use this for interactive TTY tools or to mirror a command in the visible terminal. If you pipe stdin into `docker compose exec` (e.g. `echo … | …`), add **-T** on `exec` so the pipe is used. Destructive commands are possible—same as manual use.",
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
