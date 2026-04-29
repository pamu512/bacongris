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
          "**Default way to run project commands** in the **bottom** terminal. The host only runs this via **real API `tool_calls`**, with JSON `arguments` (e.g. `text` + optional `cwd`)—**do not** pretend to invoke it with a ` ```bash ` line like `send_integrated_terminal \"…\"` (that does nothing). Send shell input; the host appends a trailing `\\n` if you omit it so a one-line **command** is actually **executed** (not left waiting at the prompt). You may still include `\\n` yourself for multiple lines. Set **cwd** to the project folder, **or** use one `cd Project && cmd` from workspace root. **If the shell may already be in that project** (e.g. after a prior `cd`), **do not** `cd Project &&` again—run `python3 -m pip install -r requirements.txt` or `python3 main.py` only. The user **sees** all output in the panel; the tool return is only *sent ok*—**the assistant does not get shell stdout in chat**; to read a workspace file, use **read_text_file** / **list_directory**, not `cat` or `ls` in the terminal (you cannot see the output; typos in long filenames are common). Ask the user to **paste** errors or summaries if you need them. Use for **pip** via `python3 -m pip`, **python3**, **docker**, **./scripts/venv_run.sh**, interactive CLIs, and any run the user should **watch**. Prefer **run_trusted_workflow** for **intelx** / **cve** when the user asked to run that stack.",
        parameters: {
          type: "object",
          properties: {
            text: {
              type: "string",
              description: "Bytes to send (include \\n to execute a command)",
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
          "Run a program with **captured** stdout/stderr in the next **tool** message (headless, not the bottom terminal). **Prefer `send_integrated_terminal`** to run the same command in the on-screen shell when the user should **see** the run. Use `run_command` for short, non-interactive invocations (e.g. `python3 -c ...`) or when the user asked for log text in the chat. **Program** must be allowlisted (Settings). For `pip install`, use **program** `python3` and **args** `[\"-m\",\"pip\",\"install\",...]` unless `pip`/`pip3` is explicitly allowed. Allowlisted `program` + `args`/`arguments` + optional `cwd`. For mutating installs, follow approval rules in the system prompt.",
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
          "**Alias of `run_command` — identical parameters and behavior.** Use when the model or README naturally says “run” with `program` + `args` (captured stdout/stderr in the next tool message; allowlisted binaries only). For interactive / Docker / menus, still use `send_integrated_terminal`.",
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
  ];
}
