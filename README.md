# Bacongris CTI Agent

Local, cross-platform desktop app for **cyber threat intelligence** workflows. It runs an **agentic** chat loop against **Ollama** and can execute **your** allowlisted scripts and read files from allowlisted directories.

## Prerequisites

- [Node.js](https://nodejs.org/) 20+
- [Rust](https://www.rust-lang.org/tools/install) stable
- Platform packages for Tauri: see [Tauri prerequisites](https://tauri.app/start/prerequisites/)
- [Ollama](https://ollama.com/) with a **tool-capable** model pulled (for example `llama3.1`)

## Development

```sh
npm install
npm run tauri dev
```

## Build

```sh
npm run tauri build
```

Installers and bundles are emitted under `src-tauri/target/release/bundle/`.

## Security model

- **Allowlisted directories** — file and `run_command` targets must resolve under configured roots (after canonicalization).
- **Allowed executables** — full paths to interpreters or binaries (for example `/usr/bin/python3`) that are permitted even when not under those roots.
- **Timeouts and output caps** — command output is truncated and runs time out per settings.
- **Audit log** — tool invocations are appended to a local JSON-lines file under your OS config directory, in `BacongrisCTIAgent/audit.log`.

This is a **local power tool**: only add roots and executables you trust.

## Workspace

The app keeps a **workspace** folder for your scripts:

- **Default location:** `<config-dir>/BacongrisCTIAgent/workspace` (created on demand).
- **Custom location:** Settings → Workspace → choose a folder or paste a path, then **Save settings**.
- **`scripts/`** inside the workspace is created when you use **Prepare folders** (or when the workspace panel loads). That entire workspace tree is **always allowlisted** for file and `run_command` tools—you do not need to duplicate it under “Allowlisted directories” unless you want an extra path elsewhere.

Use **Open in file manager** from the sidebar to drop files in from Explorer / Finder.

**Scan run requirements** (sidebar) and the agent tool **analyze_workspace_run_requirements** walk the workspace (depth-limited), look for common manifests (`requirements.txt`, `package.json`, `pyproject.toml`, Docker, Make, Conda, etc.), list shell/Python/PowerShell scripts, note `.github/workflows` YAML, and suggest typical install/run steps. This is heuristic—always verify on your machine.

## Configuration

Settings are stored as JSON under the OS config directory: `BacongrisCTIAgent/settings.json` (next to the audit log). You can edit them in the in-app **Settings** panel.

## CI

GitHub Actions runs the Vite build and `tauri build` on Ubuntu, macOS, and Windows (see `.github/workflows/ci.yml`).
