# Bacongris CTI Agent

Local, cross-platform desktop app for **cyber threat intelligence** workflows. It runs an **agentic** chat loop against **Ollama** and can execute **your** allowlisted scripts and read files from allowlisted directories.

## Install (for end users, no terminal for daily use)

**Prebuilt installers:** build locally (see [Build](#build)) or run the **Package (manual)** GitHub Action (`.github/workflows/release.yml`) to download **macOS universal `.dmg`** and **Windows NSIS `.exe`** as workflow artifacts. Public **GitHub Releases** are not created until you opt in.

**Ollama (needed for the agent):** install from [ollama.com](https://ollama.com) using the **graphical installer**; start Ollama from the menubar (macOS) or system tray (Windows) and add a model from the Ollama app if you have not already. No command line is required for that.

When you do have a **`.dmg`** (macOS) or **`.exe`** (Windows installer), install like any other desktop app: open the DMG and drag the app to **Applications**, or run the Windows setup wizard, then launch from **Launchpad** / **Start**. If macOS blocks the first launch, **right-click the app → Open** once.

## Prerequisites (build from source only)

- [Node.js](https://nodejs.org/) 20+
- [Rust](https://www.rust-lang.org/tools/install) stable
- Platform packages for Tauri: see [Tauri prerequisites](https://tauri.app/start/prerequisites/)
- [Ollama](https://ollama.com/) with a **tool-capable** model pulled (for example `llama3.1`) when you run the app

## Development

```sh
npm install
npm run tauri dev
```

## Build

**Default (current host, single architecture):**

```sh
npm run tauri build
```

**macOS universal (Apple Silicon + Intel) DMG + `.app`:**

```sh
rustup target add x86_64-apple-darwin   # once, if missing
npm run tauri:build:mac:universal
```

Output: `src-tauri/target/universal-apple-darwin/release/bundle/dmg/*.dmg` and `.../bundle/macos/*.app`. Windows **NSIS** installers are built on **Windows** (local or CI), not from a plain macOS host—use the workflow or a Windows machine.

## Security model

- **Allowlisted directories** — file and `run_command` targets must resolve under configured roots (after canonicalization).
- **Allowed executables** — full paths to interpreters or binaries (for example `/usr/bin/python3`) that are permitted even when not under those roots.
- **Timeouts and output caps** — command output is truncated and runs time out per settings.
- **Audit log** — tool invocations are appended to a local JSON-lines file under your OS config directory, in `BacongrisCTIAgent/audit.log`. Each line can include an `activeProfileId` for the workspace profile in use.

This is a **local power tool**: only add roots and executables you trust.

## Workspaces and agents (profiles)

- **`app.db`** (SQLite) in `BacongrisCTIAgent/` stores **workspace profiles** (name + on-disk path), the **active profile**, **chat agents** (separate threads per profile), and the **active agent**. First launch creates a profile from your previous **Settings → Workspace** path (or the default `…/workspace`) and a **Main** agent.
- **Conversations** are stored on disk as JSONL under `BacongrisCTIAgent/conversations/<profileId>/<agentId>.jsonl` (not in browser `localStorage`). An optional one-time import dialog can move legacy `localStorage` data into the active profile/agent.
- **L1 (user rules):** optional `USER_RULES.md` in the workspace root overrides inline rules stored on the profile in the DB. **L2 (memory):** optional `NOTES.md` in the workspace is injected in excerpt form into the system message.
- **Settings** (global Ollama URL, allowlists, etc.) are still in `settings.json` with **rolling file backups** on each save.
- The sidebar lets you **switch profile**, **add a workspace** (folder picker), **switch agent**, and **new agent**. **Issue 6 (path health):** if a profile path is missing, the UI shows a warning; use **Add workspace** or fix the path.

## Workspace

The app keeps a **workspace** folder for your scripts (or one folder per **profile**):

- **Default location:** `<config-dir>/BacongrisCTIAgent/workspace` (created on demand).
- **Custom location:** Settings → Workspace → choose a folder or paste a path, then **Save settings**.
- **`scripts/`** inside the workspace is created when you use **Prepare folders** (or when the workspace panel loads). That entire workspace tree is **always allowlisted** for file and `run_command` tools—you do not need to duplicate it under “Allowlisted directories” unless you want an extra path elsewhere.

Use **Open in file manager** from the sidebar to drop files in from Explorer / Finder.

**Scan run requirements** (sidebar) and the agent tool **analyze_workspace_run_requirements** walk the workspace (depth-limited), look for common manifests (`requirements.txt`, `package.json`, `pyproject.toml`, Docker, Make, Conda, etc.), list shell/Python/PowerShell scripts, note `.github/workflows` YAML, and suggest typical install/run steps. This is heuristic—always verify on your machine.

## Configuration

Settings are stored as JSON under the OS config directory: `BacongrisCTIAgent/settings.json` (next to the audit log). You can edit them in the in-app **Settings** panel.

## CI and packaging

- **CI** (`.github/workflows/ci.yml`) — runs the Vite build and `tauri build` on Ubuntu, macOS, and Windows for every push/PR, and **uploads installers as workflow artifacts** (`bacongris-windows-installer`, `bacongris-macos-bundle`, `bacongris-linux-packages` — appear at the bottom of the **run summary** after a green build).
- **Package** (`.github/workflows/release.yml`, **manual** via **Actions → run workflow**) — builds a **universal macOS `.dmg`** and a **Windows NSIS `.exe`**, uploaded as **workflow artifacts** (for your own testing). It does **not** create a public GitHub Release; that can be wired in when you are ready to ship.
