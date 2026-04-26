import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { useCallback, useEffect, useRef } from "react";
import "@xterm/xterm/css/xterm.css";

function b64ToUint8Array(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Chat assistants wrap commands in ```bash fences. Pasting that into a real shell
 * feeds literal backticks and ``` to bash, which treats `...` as command substitution
 * and leaves you stuck on continuation prompts (>).
 */
function sanitizeMarkdownFencedPaste(text: string): string {
  const normalized = text.replace(/\r\n/g, "\n");
  if (!normalized.includes("```")) return normalized;
  let s = normalized.trim();
  s = s.replace(/^```[\w.-]*\s*\n?/i, "");
  s = s.replace(/\n?```\s*$/i, "");
  return s.trimEnd();
}

type Props = {
  visible: boolean;
  cwd: string | null;
};

/** Attach to an existing backend PTY (e.g. started by the agent) or start a new shell. Never kills a live session. */
async function attachOrSpawnSession(
  cwd: string | null,
  cols: number,
  rows: number,
): Promise<void> {
  const c = cwd && cwd.trim() !== "" ? cwd : null;
  const active = await invoke<boolean>("terminal_is_active");
  if (active) {
    await invoke("terminal_resize", { cols, rows });
    return;
  }
  await invoke("terminal_kill").catch(() => {});
  await invoke("terminal_spawn", { cwd: c, cols, rows });
}

export function IntegratedTerminal({ visible, cwd }: Props) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const spawningRef = useRef(false);

  const startFreshSession = useCallback(async () => {
    const term = termRef.current;
    const fit = fitRef.current;
    if (!term || !fit || spawningRef.current) return;
    spawningRef.current = true;
    try {
      fit.fit();
      const c = cwd && cwd.trim() !== "" ? cwd : null;
      await invoke("terminal_kill").catch(() => {});
      term.clear();
      await invoke("terminal_spawn", {
        cwd: c,
        cols: term.cols,
        rows: term.rows,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      term.writeln(`\r\n\x1b[31m[terminal] ${msg}\x1b[0m\r\n`);
    } finally {
      spawningRef.current = false;
    }
  }, [cwd]);

  useEffect(() => {
    if (!visible) return;
    const el = wrapRef.current;
    if (!el) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily:
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      theme: {
        background: "#0a0c10",
        foreground: "#e8ecf1",
        cursor: "#5b8cff",
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const unsubsRef = { current: [] as UnlistenFn[] };
    let cancelled = false;

    const dSub = term.onData((data) => {
      void invoke("terminal_write", { data }).catch(() => {});
    });
    const rSub = term.onResize(({ cols, rows }) => {
      void invoke("terminal_resize", { cols, rows }).catch(() => {});
    });

    const onPaste = (ev: ClipboardEvent) => {
      const raw = ev.clipboardData?.getData("text/plain") ?? "";
      if (!raw.includes("```")) return;
      const cleaned = sanitizeMarkdownFencedPaste(raw);
      const normalized = raw.replace(/\r\n/g, "\n");
      if (cleaned === normalized) return;
      ev.preventDefault();
      ev.stopPropagation();
      void invoke("terminal_write", { data: cleaned }).catch(() => {});
    };
    term.textarea?.addEventListener("paste", onPaste);

    const onWinResize = () => {
      fit.fit();
    };
    window.addEventListener("resize", onWinResize);

    const ro = new ResizeObserver(() => {
      fit.fit();
    });
    ro.observe(el);

    void (async () => {
      try {
        const u1 = await listen<string>("pty-data", (ev) => {
          if (cancelled) return;
          try {
            term.write(b64ToUint8Array(ev.payload));
          } catch {
            /* ignore decode */
          }
        });
        const u2 = await listen("pty-exit", () => {
          if (cancelled) return;
          term.writeln("\r\n\x1b[90m[process exited]\x1b[0m");
        });
        if (cancelled) {
          u1();
          u2();
          return;
        }
        unsubsRef.current = [u1, u2];

        if (spawningRef.current) return;
        spawningRef.current = true;
        try {
          fit.fit();
          await attachOrSpawnSession(cwd, term.cols, term.rows);
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          term.writeln(`\r\n\x1b[31m[terminal] ${msg}\x1b[0m\r\n`);
        } finally {
          spawningRef.current = false;
        }
      } catch {
        term.writeln(
          "\r\n\x1b[33mTerminal events unavailable (open the desktop app).\x1b[0m\r\n",
        );
      }
    })();

    return () => {
      cancelled = true;
      window.removeEventListener("resize", onWinResize);
      ro.disconnect();
      dSub.dispose();
      rSub.dispose();
      term.textarea?.removeEventListener("paste", onPaste);
      for (const u of unsubsRef.current) u();
      unsubsRef.current = [];
      // Keep the backend PTY running so the agent and user are not cut off when the panel is hidden.
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [visible, cwd]);

  if (!visible) return null;

  return (
    <div className="terminal-dock" aria-label="Integrated terminal">
      <div className="terminal-toolbar">
        <span className="terminal-title">Terminal</span>
        <span
          className="terminal-cwd"
          title={
            cwd
              ? `${cwd}\n\nTip: pastes that include Markdown code fences (e.g. \`\`\`bash) are cleaned before sending to the shell.`
              : ""
          }
        >
          {cwd ? cwd : "cwd: (loading workspace…)"}
        </span>
        <div className="terminal-actions">
          <button
            type="button"
            className="btn small ghost"
            onClick={() => void startFreshSession()}
          >
            New session
          </button>
          <button
            type="button"
            className="btn small ghost"
            onClick={async () => {
              await invoke("terminal_kill").catch(() => {});
              termRef.current?.clear();
            }}
          >
            Kill
          </button>
        </div>
      </div>
      <div className="terminal-xterm-wrap" ref={wrapRef} />
    </div>
  );
}
