# Workspaces, profiles, multi-agent, and long-term context

**Status:** Design (approved direction)  
**App:** Bacongris (`…/BacongrisCTIAgent/`)

## 1. Goals

- **Cursor-like structure:** more than one logical workspace (folder) and more than one agent (chat thread) per workspace.
- **MVP** uses **file-backed JSON** under the existing app config directory; no new runtime dependency.
- **Phase 2** moves durable data to **SQLite** for queryability, history size, and RAG indexing.
- **“Learning”** is explicit, user-controlled, and auditable: **L1** (rules), **L2** (notes), plus **RAG-backed rolling context** when Phase 2 lands.

## 2. Current state (baseline)

- `settings.json` holds a single `workspacePath` (or empty → default `…/BacongrisCTIAgent/workspace`).
- `AppSettings` drives `resolve_workspace_dir`, executor allowlists, terminal cwd, and system-prompt workspace hints.
- Chat is **single global thread** in `localStorage` (autosave); no `profileId` / `agentId`.

## 3. MVP: workspace profiles and app state

### 3.1 Files (under `BacongrisCTIAgent/`)

| File | Purpose |
|------|--------|
| `settings.json` | Global app preferences: Ollama URL, model, **global** allowlisted roots / allowed executables defaults, execution limits, docker sandbox, etc. |
| `profiles.json` | **List of workspace profiles** (see below). |
| `state.json` | **Active profile id** and last-focused **agent id** (optional, for restore). Small, rewritten often. |

### 3.2 `WorkspaceProfile` (MVP)

```jsonc
{
  "id": "uuid",
  "name": "Bacongris",           // user-visible label; default from folder name
  "path": "/abs/path/to/folder", // required; must resolve to a directory
  "lastOpened": 1714147200000,  // ms epoch; update on focus/switch
  "allowlistOverrides": {        // optional; if absent, use globals only
    "extraRoots": ["..."],
    "extraExecutables": ["..."]
  }
}
```

- **Effective workspace root** for tools = `path` (same role as today’s `resolve_workspace_dir` for that profile).
- **Effective allowlist** = merge **global** `AppSettings` lists with `allowlistOverrides` (union, de-duplicated); document merge order in code.
- **Switching profile:** backend reads `state.json` → `profiles.json` → sets in-memory “active profile”; all `get_workspace_info`-style calls resolve from **active profile path**, not a single `workspacePath` in settings.

### 3.3 Migration

- If `settings.json` still has non-empty `workspacePath` and `profiles.json` is missing or empty, **auto-create** one profile from that path, name = last segment of path, then **optionally** clear or deprecate `workspacePath` in `settings` (see §3.4).
- If both empty, create a **default** profile pointing at the existing default dir `app_config_dir()/workspace` so behavior matches today.

### 3.4 `AppSettings` shape (evolution)

- **Preferred:** Remove `workspacePath` from `AppSettings` once migration exists; the only workspace root is **from active `WorkspaceProfile.path`**.
- **Transitional:** Keep `workspacePath` in JSON for one release, write-through sync when active profile changes, then remove in a follow-up PR (reduces break risk).

### 3.5 Tauri surface (MVP)

New or adjusted commands (names illustrative):

- `list_workspace_profiles` → `Vec<WorkspaceProfile>`
- `get_active_profile` / `set_active_profile { id }`
- `upsert_workspace_profile` / `remove_workspace_profile` (validation: path exists, unique `path` or `id`)
- `get_workspace_info` → uses **active profile** (no change to frontend shape of `WorkspaceInfo` beyond sourcing path)

Persist writes atomically: write temp file + `rename` where possible.

## 4. Multi-agent (sessions) — MVP (minimal)

- **Per active profile**, maintain a list of **agents** (chat sessions): `{ id, title, createdAt, updatedAt }`.
- **Messages** for that agent: JSON on disk, e.g. `agents/<profileId>/<agentId>.json` or one index file + separate message stores—MVP can be one file per agent to avoid large single JSON.
- **UI:** sidebar or secondary list: New agent, select agent, rename/delete (optional in MVP).
- **State:** `state.json` holds `activeProfileId` + `activeAgentId` for restore.
- Ties into replacing **global** `localStorage` autosave with **disk** keyed by `profileId` + `agentId`.

## 5. Phase 2: SQLite

### 5.1 Why

- Scalable history, indexed queries, transactions, and a single place for **embeddings + chunk metadata** (RAG).

### 5.2 Suggested tables (illustrative)

- `profiles` — same fields as `WorkspaceProfile`
- `agents` — `id`, `profile_id`, `title`, timestamps
- `messages` — `id`, `agent_id`, `role`, `content`, `ord`, `created_at` (or store blobs as JSON per row)
- `chunks` — `id`, `source` (e.g. `user_note`, `transcript`, `file_ref`), `text`, `agent_id` nullable, `profile_id`, `created_at`
- `embeddings` — `chunk_id`, `dim`, `vector` (BLOB) or use sqlite-vec if adopted later

**Migration path:** one-time import from `profiles.json` + per-agent JSON into SQLite; keep JSON as backup or delete after verify.

## 6. Learning: L1, L2, and RAG “context card”

### 6.1 L1 — User rules (static preferences)

- **Storage:** per-profile optional `USER_RULES.md` in workspace, **and/or** a `userRules` string field on the profile (MVP) merged into the **system** message block (same as today’s `CTI_SYSTEM_PROMPT` + workspace hint).
- **User edits** in Settings or a small editor; always visible/auditable.

### 6.2 L2 — Memory notes (appendable context)

- **Storage:** e.g. `…/BacongrisCTIAgent/memories/<profileId>.md` or `<profileId>/NOTES.md` in workspace; structured sections (“Facts”, “Open questions”).
- **Injection:** on each turn, append a bounded excerpt (char/token cap) to system or a dedicated `## Memory` block.
- **Optional tool:** “add_memory” / “update memory file” (later) so the model can append with user review.

### 6.3 RAG — rolling “context card” (Phase 2+)

- **Ingestion:** on message send/complete, chunk transcript + L2 notes; optional future: allowlisted file snippets.
- **Embeddings:** local model via Ollama (embedding endpoint) or bundled model—**decision at implementation** (must match chosen stack).
- **Per turn:** retrieve top-`k` chunks relevant to latest user message, compress into a short **“Context card”** (bullets), injected after system prompt or before user content.
- **Refresh:** re-query each turn; optionally **summarize** long threads into a rolling summary row in SQLite to cap tokens.
- **Privacy:** all local; no cloud required.

## 7. Ordering of implementation (recommended)

1. **Profiles + `state.json` + migration**; backend resolves workspace from active profile.  
2. **Frontend:** profile switcher, create/rename profile, “Open folder”.  
3. **Multi-agent JSON storage + UI**; remove reliance on a single `localStorage` key.  
4. **L1** (user rules) + **L2** (notes file) wiring into prompt.  
5. **Phase 2 SQLite** + import from JSON.  
6. **RAG** + context card (chunks + embeddings + retrieval).

## 8. Out of scope (this spec)

- Multi-window / multi-process Cursor parity.  
- Cloud sync, team sharing, or encrypted backup (unless added later).  
- Automatic learning without user visibility (contra product trust).

## 9. Open decisions (to lock at implementation time)

- Embedding model and Ollama API version for vectors.  
- Max tokens for context card, L1/L2, and RAG combined (single budget).  
- Whether `allowlistOverrides` can **narrow** globals or only **add** (recommend: **add-only** for MVP to avoid “locked out by mistake”).

---

*Spec self-review: no intentional TBDs left for core architecture; §9 lists implementation-time choices, not spec gaps.*
