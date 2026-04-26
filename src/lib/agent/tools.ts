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
          "Run a local program with arguments (no shell). Use an absolute path to the binary/script under an allowlisted directory, OR a bare name like python3/node that matches the *filename* of an entry in Settings → Allowed executables (e.g. allowed list contains /usr/bin/python3 → program can be python3). Bare `docker` (and legacy `docker-compose`) also resolve from standard install paths on macOS/Linux (Homebrew / Docker Desktop) without listing them. cwd must be under the workspace or another allowlisted root. Prefer this for non-interactive steps (including docker compose build and docker compose up -d). Long-running attached compose may hit the execution timeout — use up -d or the in-app Terminal.",
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
          "Type text into the in-app **integrated terminal** (bottom panel), like a user pasting. Creates a shell session if none exists, using **cwd** (optional) or the configured workspace. Append a newline (\\n) in **text** to run a line (e.g. \"cd CVE_Project_NVD && python3 main.py\\n\"). Output streams to the panel; this tool only confirms it was sent. For unattended runs without a TTY, prefer **run_command**; use this for interactive tools or to mirror a command in the visible terminal. Destructive commands are possible—same as manual use.",
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
  ];
}
