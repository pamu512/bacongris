//! Heuristic scan of the workspace for run requirements (deps, workflows, scripts).
//!
//! **Scan modes (see `analyze_workspace_run_requirements`):**
//! - **index** (default) — one pass over direct subfolders: each top-level directory is a “workflow”
//!   with at-a-glance manifests. Fast; use `workflowRelativePath` for a deep scan of one project.
//! - **scoped** — deep scan (depth-limited) under a single `workflowRelativePath` under the workspace.
//! - **full** — deep scan the entire workspace (the previous behavior). Cached by file-tree fingerprint
//!   so unchanged trees are not re-read on every call.

use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::audit::append_audit;
use crate::settings::{load_settings, resolve_workspace_dir};

const MAX_SCAN_DEPTH: usize = 5;
const MAX_FILES_COLLECTED: usize = 800;
const MAX_READ_BYTES: usize = 256 * 1024;

const INDEX_CANDIDATE_MANIFESTS: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "Makefile",
    "README.md",
    "README.txt",
];

type AnalysisCacheMap = std::collections::HashMap<String, (u64, WorkspaceRunAnalysis)>;
fn analysis_cache() -> &'static Mutex<AnalysisCacheMap> {
    static CACHE: OnceLock<Mutex<AnalysisCacheMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(AnalysisCacheMap::new()))
}

/// File-tree content fingerprint: directory walk and metadata only (no file reads). Used to skip
/// redundant full/scoped scans when nothing on disk has changed.
fn tree_fingerprint(root: &Path, workspace: &Path) -> Result<u64, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(root, 0, &mut files)?;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset
    for p in files {
        let rel = rel_path(workspace, p.as_path());
        h = fnv1a64_append(h, &rel);
        let meta = fs::metadata(p).map_err(|e| format!("metadata: {e}"))?;
        h = h.wrapping_mul(0x1000_0001_b3);
        h ^= meta.len();
        h = h.wrapping_mul(0x1000_0001_b3);
        h ^= mtime_nanos(&meta);
    }
    Ok(h)
}

fn mtime_nanos(m: &fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|s| s.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn fnv1a64_append(mut h: u64, s: &str) -> u64 {
    const FNV_PRIME: u64 = 0x1000_0001_b3;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn cache_key(workspace: &str, kind: &str) -> String {
    format!("{}\n{}", workspace, kind)
}

/// Build a child path of `workspace` from a path relative to the workspace. Rejects `..`.
fn safe_subpath(workspace: &Path, rel: &str) -> Result<PathBuf, String> {
    let t = rel.trim();
    if t.is_empty() {
        return Err("empty workflow path".to_string());
    }
    if t.contains("..") {
        return Err("workflow path may not contain ..".to_string());
    }
    let wcan = dunce::canonicalize(workspace)
        .map_err(|e| format!("resolve workspace: {e}"))?;
    let mut acc = wcan.clone();
    for s in t.replace('\\', "/").split('/') {
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            return Err("path leaves the workspace".to_string());
        }
        acc = acc.join(s);
    }
    if !acc.starts_with(&wcan) {
        return Err("path leaves the workspace".to_string());
    }
    Ok(acc)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowIndexEntry {
    pub relative_path: String,
    /// Short human-readable hint (manifests, entrypoints).
    pub summary: String,
    /// Relevant files seen at the project root, relative to the workspace.
    pub key_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRunAnalysis {
    /// `index` | `scoped` | `full` — which scan strategy produced this result.
    pub scan_mode: String,
    /// True if this exact tree was served from the in-process cache (fingerprint match).
    pub cache_hit: bool,
    /// Populated in **index** mode: one row per top-level subfolder of the workspace.
    pub workflow_index: Option<Vec<WorkflowIndexEntry>>,
    pub workspace_root: String,
    pub scripts_dir: String,
    pub manifest_files: Vec<ManifestFinding>,
    pub runnable_scripts: Vec<RunnableScriptHint>,
    pub workflow_hints: Vec<String>,
    pub suggested_steps: Vec<String>,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFinding {
    pub relative_path: String,
    pub kind: String,
    pub summary: String,
    pub excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnableScriptHint {
    pub relative_path: String,
    pub shebang: Option<String>,
    pub inferred_runtime: Option<String>,
}

fn should_skip_dir(name: &str) -> bool {
    if name == ".github" {
        return false;
    }
    matches!(
        name,
        "node_modules"
            | "__pycache__"
            | ".venv"
            | "venv"
            | "env"
            | ".env"
            | "target"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".ruff_cache"
            | "dist"
            | "build"
            | ".tox"
            | ".git"
    ) || (name.starts_with('.') && name != ".github")
}

fn collect_files(root: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if depth > MAX_SCAN_DEPTH || out.len() >= MAX_FILES_COLLECTED {
        return Ok(());
    }
    let read = fs::read_dir(root).map_err(|e| format!("read_dir {}: {e}", root.display()))?;
    for ent in read {
        let ent = ent.map_err(|e| format!("dir entry: {e}"))?;
        let path = ent.path();
        let name = ent.file_name().to_string_lossy().into_owned();
        let is_dir = ent
            .file_type()
            .map(|t| t.is_dir())
            .unwrap_or(false);
        if is_dir {
            if should_skip_dir(&name) {
                continue;
            }
            collect_files(&path, depth + 1, out)?;
        } else {
            out.push(path);
            if out.len() >= MAX_FILES_COLLECTED {
                break;
            }
        }
    }
    Ok(())
}

fn rel_path(workspace: &Path, p: &Path) -> String {
    dunce::canonicalize(p)
        .ok()
        .and_then(|c| {
            dunce::canonicalize(workspace).ok().and_then(|w| {
                c.strip_prefix(&w)
                    .ok()
                    .map(|s| s.to_string_lossy().into_owned())
            })
        })
        .or_else(|| {
            p.strip_prefix(workspace)
                .ok()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

fn read_capped(p: &Path) -> Result<String, String> {
    let meta = fs::metadata(p).map_err(|e| format!("metadata: {e}"))?;
    if meta.len() > MAX_READ_BYTES as u64 {
        return Err(format!(
            "file too large for scan ({} bytes): {}",
            meta.len(),
            p.display()
        ));
    }
    fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))
}

fn classify_manifest(file_name: &str) -> Option<&'static str> {
    Some(match file_name {
        "requirements.txt" => "pip-requirements",
        "constraints.txt" => "pip-constraints",
        "pyproject.toml" => "pyproject",
        "Pipfile" => "pipfile",
        "poetry.lock" => "poetry-lock",
        "setup.py" => "setuptools",
        "environment.yml" | "environment.yaml" => "conda-env",
        "package.json" => "npm-package",
        "package-lock.json" => "npm-lock",
        "pnpm-lock.yaml" => "pnpm-lock",
        "yarn.lock" => "yarn-lock",
        "Cargo.toml" => "cargo",
        "go.mod" => "go-module",
        "Gemfile" => "bundler",
        "composer.json" => "composer",
        "Makefile" => "make",
        "justfile" | "Justfile" => "just",
        "Taskfile.yml" | "Taskfile.yaml" => "task",
        "Dockerfile" => "dockerfile",
        "docker-compose.yml" | "docker-compose.yaml" => "docker-compose",
        ".python-version" => "pyenv-version",
        ".nvmrc" => "nvmrc",
        "runtime.txt" => "heroku-runtime",
        "README.md" | "README.markdown" | "README.rst" | "README.txt" => "readme",
        _ => {
            if file_name.starts_with("requirements") && file_name.ends_with(".txt") {
                "pip-requirements"
            } else {
                return None;
            }
        }
    })
}

fn analyze_requirements_txt(content: &str, rel: &str) -> ManifestFinding {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(40)
        .collect();
    let n = content
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count();
    let preview = lines.join("\n");
    let excerpt = if preview.len() > 1200 {
        Some(format!("{}…", &preview[..1200]))
    } else if preview.is_empty() {
        None
    } else {
        Some(preview)
    };
    ManifestFinding {
        relative_path: rel.to_string(),
        kind: "pip-requirements".into(),
        summary: format!("{n} non-comment requirement line(s); typical install: pip install -r {rel}"),
        excerpt,
    }
}

fn analyze_package_json(content: &str, rel: &str) -> Result<ManifestFinding, String> {
    let v: JsonValue = serde_json::from_str(content).map_err(|e| format!("package.json: {e}"))?;
    let mut parts = Vec::new();
    if let Some(name) = v.get("name").and_then(|x| x.as_str()) {
        parts.push(format!("package: {name}"));
    }
    if let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) {
        let keys: Vec<&str> = scripts.keys().map(String::as_str).take(12).collect();
        if !keys.is_empty() {
            parts.push(format!("npm scripts: {}", keys.join(", ")));
        }
    }
    if let Some(eng) = v.get("engines").and_then(|e| e.as_object()) {
        let e: Vec<String> = eng
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("?")))
            .collect();
        if !e.is_empty() {
            parts.push(format!("engines: {}", e.join(", ")));
        }
    }
    let dep_count = v
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    let dev_count = v
        .get("devDependencies")
        .and_then(|d| d.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    if dep_count + dev_count > 0 {
        parts.push(format!(
            "dependencies: {dep_count}, devDependencies: {dev_count}"
        ));
    }
    Ok(ManifestFinding {
        relative_path: rel.to_string(),
        kind: "npm-package".into(),
        summary: parts.join(" · "),
        excerpt: None,
    })
}

fn analyze_pyproject(content: &str, rel: &str) -> ManifestFinding {
    let mut in_deps = false;
    let mut buf = String::new();
    for line in content.lines().take(200) {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t.contains("dependencies")
                || t.contains("project")
                || t.contains("poetry");
        }
        if in_deps {
            buf.push_str(line);
            buf.push('\n');
            if buf.len() > 1500 {
                break;
            }
        }
    }
    ManifestFinding {
        relative_path: rel.to_string(),
        kind: "pyproject".into(),
        summary: "pyproject.toml present — check [project]/Poetry/pip sections for deps and entry points".into(),
        excerpt: if buf.trim().is_empty() {
            None
        } else {
            Some(buf)
        },
    }
}

fn analyze_makefile(content: &str, rel: &str) -> ManifestFinding {
    let targets: Vec<&str> = content
        .lines()
        .filter_map(|l| {
            let l = l.trim_end();
            if l.starts_with('\t') || l.starts_with('#') || l.is_empty() {
                return None;
            }
            let head = l.split(':').next()?.trim();
            if head.contains('=') || head.starts_with('.') {
                return None;
            }
            Some(head)
        })
        .take(15)
        .collect();
    ManifestFinding {
        relative_path: rel.to_string(),
        kind: "make".into(),
        summary: format!(
            "Makefile targets (sample): {}",
            if targets.is_empty() {
                "(none detected)".into()
            } else {
                targets.join(", ")
            }
        ),
        excerpt: None,
    }
}

fn analyze_dockerfile(content: &str, rel: &str) -> ManifestFinding {
    let head: String = content.lines().take(25).collect::<Vec<_>>().join("\n");
    ManifestFinding {
        relative_path: rel.to_string(),
        kind: "dockerfile".into(),
        summary: "Dockerfile — image build/run may encode system deps and run commands".into(),
        excerpt: Some(if head.len() > 1200 {
            format!("{}…", &head[..1200])
        } else {
            head
        }),
    }
}

fn shebang_runtime(line: &str) -> Option<String> {
    let l = line.trim();
    if !l.starts_with("#!") {
        return None;
    }
    let rest = l.strip_prefix("#!")?.trim();
    Some(
        rest.split_whitespace()
            .last()
            .unwrap_or(rest)
            .rsplit('/')
            .next()
            .unwrap_or(rest)
            .to_string(),
    )
}

fn build_suggested_steps(findings: &[ManifestFinding], scripts: &[RunnableScriptHint]) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for f in findings {
        let s = match f.kind.as_str() {
            "pip-requirements" => Some(format!(
                "Python: create a venv if needed, then pip install -r {}",
                f.relative_path
            )),
            "pipfile" => Some("Python: pip install pipenv && pipenv install".into()),
            "conda-env" => Some(format!("Conda: conda env create -f {}", f.relative_path)),
            "npm-package" => Some(format!(
                "Node: in directory containing {}, run npm install (or pnpm/yarn per lockfile)",
                f.relative_path
            )),
            "cargo" => Some("Rust: cargo build (or cargo run) from the crate directory".into()),
            "go-module" => Some("Go: go run . or go build in the module directory".into()),
            "bundler" => Some("Ruby: bundle install".into()),
            "composer" => Some("PHP: composer install".into()),
            "make" => Some(format!(
                "Make: make -f {} (or run a specific target)",
                f.relative_path
            )),
            "docker-compose" => Some(format!("Docker: docker compose -f {} up", f.relative_path)),
            "dockerfile" => Some("Docker: docker build using this Dockerfile's directory as context".into()),
            "pyproject" => Some("Python: consider pip install -e . or poetry install depending on the file".into()),
            "readme" => Some(format!("Read {} for setup and run instructions", f.relative_path)),
            _ => None,
        };
        if let Some(st) = s {
            if seen.insert(st.clone()) {
                steps.push(st);
            }
        }
    }
    if !scripts.is_empty() {
        steps.push(
            "Scripts: use run_command with the interpreter from shebang (or allowed_executables) and script path."
                .into(),
        );
    }
    steps
}

/// Deep heuristics: walk `scan_root` (and subtrees) but emit paths relative to `workspace` (the configured root).
fn run_deep_file_scan(
    workspace: &Path,
    scan_root: &Path,
) -> Result<
    (
        Vec<ManifestFinding>,
        Vec<RunnableScriptHint>,
        Vec<String>,
        Vec<String>,
    ),
    String,
> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(scan_root, 0, &mut files)?;
    let mut manifest_files: Vec<ManifestFinding> = Vec::new();
    let mut runnable_scripts: Vec<RunnableScriptHint> = Vec::new();
    let mut workflow_hints: Vec<String> = Vec::new();
    let mut caveats: Vec<String> = vec![
        "This scan is heuristic — verify versions, secrets, and network access yourself.".into(),
    ];

    for p in &files {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let rel = rel_path(workspace, p);

        if rel.contains(".github/workflows") && (name.ends_with(".yml") || name.ends_with(".yaml")) {
            workflow_hints.push(format!("CI workflow file: {rel}"));
            continue;
        }

        if name.ends_with(".sh") || name.ends_with(".bash") || name.ends_with(".zsh") {
            if let Ok(content) = read_capped(p) {
                let first = content.lines().next().unwrap_or("").to_string();
                let shebang = if first.starts_with("#!") {
                    Some(first.clone())
                } else {
                    None
                };
                runnable_scripts.push(RunnableScriptHint {
                    relative_path: rel.clone(),
                    shebang: shebang.clone(),
                    inferred_runtime: shebang_runtime(&first),
                });
            }
            continue;
        }

        if name.ends_with(".py") {
            runnable_scripts.push(RunnableScriptHint {
                relative_path: rel.clone(),
                shebang: None,
                inferred_runtime: Some("python".into()),
            });
            continue;
        }
        if name.ends_with(".ps1") {
            runnable_scripts.push(RunnableScriptHint {
                relative_path: rel.clone(),
                shebang: None,
                inferred_runtime: Some("powershell".into()),
            });
            continue;
        }

        let Some(kind) = classify_manifest(name) else {
            continue;
        };

        let content = match read_capped(p) {
            Ok(c) => c,
            Err(e) => {
                caveats.push(format!("Skipped {}: {e}", rel));
                continue;
            }
        };

        let finding = match kind {
            "pip-requirements" | "pip-constraints" => analyze_requirements_txt(&content, &rel),
            "npm-package" => analyze_package_json(&content, &rel).unwrap_or(ManifestFinding {
                relative_path: rel.clone(),
                kind: "npm-package".into(),
                summary: "package.json could not be parsed".into(),
                excerpt: None,
            }),
            "pyproject" => analyze_pyproject(&content, &rel),
            "make" => analyze_makefile(&content, &rel),
            "dockerfile" => analyze_dockerfile(&content, &rel),
            "readme" => ManifestFinding {
                relative_path: rel.clone(),
                kind: "readme".into(),
                summary: "README may describe setup, env vars, and how to run workflows".into(),
                excerpt: Some(
                    content
                        .lines()
                        .take(45)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            },
            "conda-env" | "pipfile" | "docker-compose" | "npm-lock" | "pnpm-lock" | "yarn-lock"
            | "cargo" | "go-module" | "Gemfile" | "composer" | "setuptools" | "poetry-lock"
            | "pyenv-version" | "nvmrc" | "heroku-runtime" | "just" | "task" => ManifestFinding {
                relative_path: rel.clone(),
                kind: kind.into(),
                summary: format!("Found {kind} at {rel} — open with read_text_file for full contents"),
                excerpt: Some(
                    content
                        .chars()
                        .take(900)
                        .collect::<String>()
                        + if content.len() > 900 { "…" } else { "" },
                ),
            },
            _ => ManifestFinding {
                relative_path: rel.clone(),
                kind: kind.into(),
                summary: format!("Detected {kind}"),
                excerpt: None,
            },
        };
        manifest_files.push(finding);
    }

    Ok((
        manifest_files,
        runnable_scripts,
        workflow_hints,
        caveats,
    ))
}

/// One row per top-level subfolder: typical layout when the workspace is a “collection of projects”
/// (e.g. All_Scripts/ASM-fetch, All_Scripts/CVE_Project_NVD) without recursing the whole tree.
fn run_index_only(workspace: &Path) -> Result<
    (
        Vec<WorkflowIndexEntry>,
        Vec<ManifestFinding>,
        Vec<RunnableScriptHint>,
        Vec<String>,
    ),
    String
> {
    let mut index_rows: Vec<WorkflowIndexEntry> = Vec::new();
    let mut manifest_files: Vec<ManifestFinding> = Vec::new();
    let mut runnable_scripts: Vec<RunnableScriptHint> = Vec::new();
    let read = fs::read_dir(workspace).map_err(|e| format!("read_dir workspace: {e}"))?;
    for ent in read {
        let ent = ent.map_err(|e| format!("dir entry: {e}"))?;
        if !ent
            .file_type()
            .map(|t| t.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if should_skip_dir(&name) {
            continue;
        }
        let dir = ent.path();
        let rel_dir = rel_path(workspace, &dir);
        if rel_dir == "scripts" {
            // Still index scripts/ as a “workflow” if the user curates it.
        }

        let mut key: Vec<String> = Vec::new();
        for fname in INDEX_CANDIDATE_MANIFESTS {
            let fpath = dir.join(*fname);
            if !fpath.is_file() {
                continue;
            }
            key.push(format!("{rel_dir}/{}", fpath.file_name().unwrap().to_string_lossy()));
        }
        for extra in [".github"] {
            let p = dir.join(extra);
            if p.is_dir() {
                key.push(format!("{rel_dir}/{extra}"));
            }
        }

        let mpy = dir.join("main.py");
        if mpy.is_file() {
            let rel = rel_path(workspace, mpy.as_path());
            key.push(format!("{rel} (entry)"));
            runnable_scripts.push(RunnableScriptHint {
                relative_path: rel,
                shebang: None,
                inferred_runtime: Some("python".into()),
            });
        }

        for fname in INDEX_CANDIDATE_MANIFESTS {
            let fpath = dir.join(fname);
            if !fpath.is_file() {
                continue;
            }
            let rel = rel_path(workspace, &fpath);
            if matches!(*fname, "README.md" | "README.txt") {
                // Short README: short excerpt in manifest only (avoid massive JSON).
                if let Ok(content) = read_capped(&fpath) {
                    manifest_files.push(ManifestFinding {
                        relative_path: rel.clone(),
                        kind: "readme".into(),
                        summary: "README (top-level) — use read_text_file for full file".into(),
                        excerpt: Some(
                            content
                                .lines()
                                .take(10)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        ),
                    });
                }
            } else if *fname == "requirements.txt" {
                if let Ok(c) = read_capped(&fpath) {
                    manifest_files.push(analyze_requirements_txt(&c, &rel));
                }
            } else if *fname == "package.json" {
                if let Ok(c) = read_capped(&fpath) {
                    if let Ok(f) = analyze_package_json(&c, &rel) {
                        manifest_files.push(f);
                    }
                }
            } else if *fname == "pyproject.toml" {
                if let Ok(c) = read_capped(&fpath) {
                    manifest_files.push(analyze_pyproject(&c, &rel));
                }
            } else if *fname == "docker-compose.yml" || *fname == "docker-compose.yaml" {
                if let Ok(c) = read_capped(&fpath) {
                    let kind = "docker-compose";
                    manifest_files.push(ManifestFinding {
                        relative_path: rel.clone(),
                        kind: kind.into(),
                        summary: format!("Found {kind} at {rel} (index) — open for full file"),
                        excerpt: Some(
                            c.chars().take(400).collect::<String>()
                                + if c.len() > 400 { "…" } else { "" },
                        ),
                    });
                }
            } else if *fname == "Dockerfile" {
                if let Ok(c) = read_capped(&fpath) {
                    let head: String = c.lines().take(8).collect::<Vec<_>>().join("\n");
                    manifest_files.push(ManifestFinding {
                        relative_path: rel.clone(),
                        kind: "dockerfile".into(),
                        summary: "Dockerfile (top level)".into(),
                        excerpt: Some(
                            if head.len() > 500 {
                                format!("{}…", &head[..500])
                            } else {
                                head
                            },
                        ),
                    });
                }
            } else if *fname == "Makefile" {
                if let Ok(c) = read_capped(&fpath) {
                    manifest_files.push(analyze_makefile(&c, &rel));
                }
            }
        }

        let has_req = key.iter().any(|k| k.contains("requirements.txt"));
        let has_docker = key.iter().any(|k| k.contains("docker-compose") || k.contains("Dockerfile"));
        let has_readme = key
            .iter()
            .any(|k| k.to_lowercase().contains("readme"));
        let mut parts: Vec<&str> = Vec::new();
        if has_req { parts.push("Python deps (requirements)"); }
        if has_docker { parts.push("Docker"); }
        if has_readme { parts.push("README"); }
        if mpy.is_file() { parts.push("main.py entry"); }
        if parts.is_empty() { parts.push("no common manifests at this folder’s root"); }
        let summary = format!("{} — {}", rel_dir, parts.join(", "));

        index_rows.push(WorkflowIndexEntry {
            relative_path: rel_dir,
            summary,
            key_files: key,
        });
    }
    let mut extra = vec![
        "This index only inspects the root of each top-level folder (not every nested subfolder).".into(),
        "For a full subfolder scan, pass workflowRelativePath (e.g. \"Phishing_.../screenshots\" or \"CVE_Project_NVD\").".into(),
        "For a scan of the whole workspace, pass fullWorkspace: true (or use the sidebar).".into(),
    ];
    if index_rows.is_empty() {
        extra.push("No project subfolders found; try fullWorkspace, or add directories under the workspace root.".into());
    }
    Ok((
        index_rows,
        manifest_files,
        runnable_scripts,
        extra,
    ))
}

fn append_suggested_workflow_note(s: &mut Vec<String>, text: &str) {
    if !s.iter().any(|x| x == text) {
        s.push(text.to_string());
    }
}

#[tauri::command]
pub fn analyze_workspace_run_requirements(
    app: tauri::AppHandle,
    workflow_relative_path: Option<String>,
    full_workspace: Option<bool>,
    use_cache: Option<bool>,
) -> Result<WorkspaceRunAnalysis, String> {
    let settings = load_settings(&app)?;
    let root = resolve_workspace_dir(&settings)?;
    fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts_dir = root.join("scripts");
    fs::create_dir_all(&scripts_dir).map_err(|e| format!("scripts: {e}"))?;
    let root_s = root.to_string_lossy().into_owned();
    let use_cache = use_cache.unwrap_or(true);
    let full = full_workspace.unwrap_or(false);

    if full {
        let kind = "full";
        let k = cache_key(&root_s, kind);
        if use_cache {
            if let Ok(g) = tree_fingerprint(&root, &root) {
                if let Ok(cache) = analysis_cache().lock() {
                    if let Some((fp, a)) = cache.get(&k) {
                        if *fp == g {
                            let mut out = a.clone();
                            out.cache_hit = true;
                            let _ = append_audit(
                                &app,
                                "analyze_workspace_run_requirements",
                                serde_json::json!({ "mode": "full", "cacheHit": true }),
                            );
                            return Ok(out);
                        }
                    }
                }
            }
        }
        let (m, r, w, cave) = run_deep_file_scan(&root, &root)?;
        let mut sugg = build_suggested_steps(&m, &r);
        append_suggested_workflow_note(
            &mut sugg,
            "Lighter next time: call without fullWorkspace for a top-level project index, or set workflowRelativePath to deep-scan one subfolder only.",
        );
        let analysis = WorkspaceRunAnalysis {
            scan_mode: "full".into(),
            cache_hit: false,
            workflow_index: None,
            workspace_root: root_s.clone(),
            scripts_dir: scripts_dir.to_string_lossy().into_owned(),
            manifest_files: m,
            runnable_scripts: r,
            workflow_hints: w,
            suggested_steps: sugg,
            caveats: cave,
        };
        if use_cache {
            if let Ok(fp) = tree_fingerprint(&root, &root) {
                if let Ok(mut c) = analysis_cache().lock() {
                    c.insert(k, (fp, analysis.clone()));
                }
            }
        }
        let _ = append_audit(
            &app,
            "analyze_workspace_run_requirements",
            serde_json::json!({
                "mode": "full",
                "cacheHit": false,
                "manifestCount": analysis.manifest_files.len(),
                "scriptCount": analysis.runnable_scripts.len(),
            }),
        );
        return Ok(analysis);
    }

    if let Some(ref r) = workflow_relative_path {
        let t = r.trim();
        if !t.is_empty() {
            let sub = safe_subpath(&root, t)?;
            if !sub.is_dir() {
                return Err(format!("not a directory: {}", sub.display()));
            }
            let kind = format!("scoped:{}", t);
            let k = cache_key(&root_s, &kind);
            if use_cache {
                if let Ok(g) = tree_fingerprint(&sub, &root) {
                    if let Ok(c) = analysis_cache().lock() {
                        if let Some((fp, a)) = c.get(&k) {
                            if *fp == g {
                                let mut out = a.clone();
                                out.cache_hit = true;
                                let _ = append_audit(
                                    &app,
                                    "analyze_workspace_run_requirements",
                                    serde_json::json!({ "mode": "scoped", "path": t, "cacheHit": true }),
                                );
                                return Ok(out);
                            }
                        }
                    }
                }
            }
            let (m, r, w, cave) = run_deep_file_scan(&root, &sub)?;
            let mut sugg = build_suggested_steps(&m, &r);
            append_suggested_workflow_note(
                &mut sugg,
                "This result is limited to the chosen workflow path; use the default (index) or fullWorkspace to see all projects.",
            );
            let analysis = WorkspaceRunAnalysis {
                scan_mode: "scoped".into(),
                cache_hit: false,
                workflow_index: None,
                workspace_root: root_s.clone(),
                scripts_dir: scripts_dir.to_string_lossy().into_owned(),
                manifest_files: m,
                runnable_scripts: r,
                workflow_hints: w,
                suggested_steps: sugg,
                caveats: cave,
            };
            if use_cache {
                if let Ok(fp) = tree_fingerprint(&sub, &root) {
                    if let Ok(mut c) = analysis_cache().lock() {
                        c.insert(k, (fp, analysis.clone()));
                    }
                }
            }
            let _ = append_audit(
                &app,
                "analyze_workspace_run_requirements",
                serde_json::json!({
                    "mode": "scoped",
                    "path": t,
                    "cacheHit": false,
                    "manifestCount": analysis.manifest_files.len(),
                    "scriptCount": analysis.runnable_scripts.len(),
                }),
            );
            return Ok(analysis);
        }
    }

    // Default: index of top-level “workflow” directories (fast, not cached).
    let (idx, m, r, extra) = run_index_only(&root)?;
    let mut cave = vec!["This scan is heuristic — verify versions, secrets, and network access yourself.".into()];
    cave.extend(extra);
    let mut sugg = build_suggested_steps(&m, &r);
    append_suggested_workflow_note(
        &mut sugg,
        "Top-level index only. Deep-scan a single project with workflowRelativePath (e.g. \"CVE_Project_NVD\"). The workspace root can change; paths are always relative to that root.",
    );
    let analysis = WorkspaceRunAnalysis {
        scan_mode: "index".into(),
        cache_hit: false,
        workflow_index: Some(idx),
        workspace_root: root_s,
        scripts_dir: scripts_dir.to_string_lossy().into_owned(),
        manifest_files: m,
        runnable_scripts: r,
        workflow_hints: vec![],
        suggested_steps: sugg,
        caveats: cave,
    };
    let _ = append_audit(
        &app,
        "analyze_workspace_run_requirements",
        serde_json::json!({
            "mode": "index",
            "projectRowCount": analysis.workflow_index.as_ref().map(|v| v.len()).unwrap_or(0),
            "manifestCount": analysis.manifest_files.len(),
        }),
    );
    Ok(analysis)
}
