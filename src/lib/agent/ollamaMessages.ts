import { mergeUserMessageForModel } from "../chatAttachments";
import type { OllamaMessage, OllamaToolCall } from "./types";
import { canonicalizeHallucinatedToolName } from "./toolCallFallback";

/**
 * `{"a":1}\n{"b":2}` and similar: models sometimes concatenate several JSON values in one
 * `function.arguments` string. A single `JSON.parse` fails; Ollama may 500 on resend. We
 * take the first parseable top-level object (sufficient for write_text_file / one-shot tools).
 * Mirrors `splitTopLevelJsonObjects` in `toolCallFallback.ts` (kept here to avoid import cycles).
 */
function splitTopLevelJsonObjects(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === "{") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        out.push(s.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return out;
}

/** Models sometimes wrap tool JSON in markdown fences; Ollama rejects the leading `` ` `` as JSON. */
export function stripMarkdownCodeFenceFromToolArgs(s: string): string {
  let t = s.trim();
  if (!t.startsWith("```")) return t;
  const firstNl = t.indexOf("\n");
  if (firstNl !== -1) {
    t = t.slice(firstNl + 1);
  }
  const close = t.indexOf("```");
  if (close !== -1) {
    t = t.slice(0, close);
  }
  return t.trim();
}

function tryParseFirstJsonObject(t: string): Record<string, unknown> | null {
  const stripped = stripMarkdownCodeFenceFromToolArgs(t);
  const pieces = splitTopLevelJsonObjects(stripped);
  for (const p of pieces) {
    try {
      const v: unknown = JSON.parse(p);
      if (v && typeof v === "object" && !Array.isArray(v)) {
        return v as Record<string, unknown>;
      }
    } catch {
      /* next slice */
    }
  }
  return null;
}

/**
 * Remove bytes/Chars that have caused client or Ollama JSON issues; fix lone UTF-16 surrogates.
 */
export function sanitizeOllamaText(s: string): string {
  if (!s) return s;
  return s
    .replace(/\0/g, "")
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, "\uFFFD")
    .replace(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD");
}

/**
 * Newer Ollama builds expect `tool_calls[].function.arguments` as a **JSON object** in the
 * request body, not a string. Sending a string (or broken JSON text) can yield HTTP 400:
 * "Value looks like object, but can't find closing '}' symbol".
 * @see https://github.com/ollama/ollama (tool round-trip issues)
 */
export function normalizeToolArgumentsForWire(
  args: string | Record<string, unknown> | readonly unknown[] | undefined,
): Record<string, unknown> {
  if (args == null) return {};
  if (Array.isArray(args)) {
    return {
      _host_array_arguments: true,
      items: args.slice(0, 500),
    };
  }
  if (typeof args === "object" && !Array.isArray(args)) {
    return { ...args };
  }
  if (typeof args === "string") {
    const t = stripMarkdownCodeFenceFromToolArgs(args);
    if (!t) return {};
    try {
      const parsed: unknown = JSON.parse(t);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
      return { value: parsed };
    } catch {
      const firstObj = tryParseFirstJsonObject(args.trim());
      if (firstObj) {
        return { ...firstObj };
      }
      return {
        _host_repaired: true,
        _note: "Model sent non-JSON or truncated tool arguments; host replaced for Ollama API.",
        _raw: t.slice(0, 8_000),
      };
    }
  }
  return {};
}

/**
 * Coerce `tool_calls` for `/api/chat`: arguments must be a **single** JSON object (Ollama rejects
 * some multi-object `arguments` strings with HTTP 500: `invalid character '{' after top-level
 * value`). Use on **outgoing** requests and on **stored** assistant turns so the next round
 * is safe.
 */
/** Some models echo `list_directory` JSON rows as `tool_calls`; Ollama then 500s parsing them. */
function isPlausibleOllamaToolCall(tc: OllamaToolCall): boolean {
  const t = tc as unknown as Record<string, unknown>;
  if (typeof t.name === "string" && typeof t.isDir === "boolean" && !t.function) {
    return false;
  }
  const fn = t.function;
  if (!fn || typeof fn !== "object" || Array.isArray(fn)) return false;
  const f = fn as Record<string, unknown>;
  const nm = f.name;
  if (typeof nm !== "string" || !nm.trim()) return false;
  if ("isDir" in f && typeof f.isDir === "boolean" && f.arguments == null) {
    return false;
  }
  return true;
}

export function normalizeToolCallsForWire(
  calls: OllamaToolCall[] | undefined,
): OllamaToolCall[] | undefined {
  if (!calls?.length) return calls;
  const plausible = calls.filter(isPlausibleOllamaToolCall);
  if (!plausible.length) return undefined;
  return plausible.map((tc) => {
    const argumentsObj = normalizeToolArgumentsForWire(
      tc.function?.arguments as string | Record<string, unknown> | readonly unknown[] | undefined,
    );
    const rawName = String(tc.function?.name ?? "").trim();
    const name = canonicalizeHallucinatedToolName(rawName, argumentsObj);
    return {
      ...tc,
      type: (tc.type ?? "function") as "function",
      function: {
        ...tc.function,
        name,
        arguments: argumentsObj,
      },
    };
  });
}

const MAX_ASSISTANT_TEXT = 24_000;

export function prepareForOllamaRequest(m: OllamaMessage): OllamaMessage {
  const { localId: _id, thinking: _thinking, ...rest } = m;
  if (rest.role === "system") {
    return {
      ...rest,
      content:
        rest.content != null ? sanitizeOllamaText(String(rest.content)) : rest.content,
    };
  }
  if (rest.role === "user") {
    const { attachments: _att, ...userRest } = rest;
    const rawText = userRest.content != null ? String(userRest.content) : "";
    const merged = mergeUserMessageForModel(rawText, _att);
    const out =
      merged.trim().length > 0
        ? merged
        : rawText.trim().length > 0
          ? rawText
          : " ";
    return {
      role: "user",
      content: sanitizeOllamaText(out),
    };
  }
  if (rest.role === "assistant") {
    const tool_calls = normalizeToolCallsForWire(rest.tool_calls);
    if (tool_calls?.length) {
      return {
        ...rest,
        tool_calls,
        // OpenAI-style: tool-only turns do not need prose; long CoT + tools has triggered Ollama 500s.
        content: "",
      };
    }
    let c = rest.content != null ? sanitizeOllamaText(String(rest.content)) : rest.content;
    if (c && c.length > MAX_ASSISTANT_TEXT) {
      c = `${c.slice(0, MAX_ASSISTANT_TEXT)}\n[… assistant text truncated for model context …]`;
    }
    return { ...rest, content: c };
  }
  if (rest.role === "tool") {
    let c = rest.content != null ? sanitizeOllamaText(String(rest.content)) : rest.content;
    // Large tool JSON encourages the next model turn to echo it as bogus `tool_calls` → Ollama 500.
    const maxTool = 14_000;
    if (c && c.length > maxTool) {
      const n = c.length;
      c = `${c.slice(0, maxTool)}\n[… tool output truncated (${n} chars) for model context …]`;
    }
    return { ...rest, content: c };
  }
  return rest;
}
