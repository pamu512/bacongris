import { mergeUserMessageForModel } from "../chatAttachments";
import type { OllamaMessage, OllamaToolCall } from "./types";

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
  args: string | Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (args == null) return {};
  if (typeof args === "object" && !Array.isArray(args)) {
    return { ...args };
  }
  if (typeof args === "string") {
    const t = args.trim();
    if (!t) return {};
    try {
      const parsed: unknown = JSON.parse(t);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
      return { value: parsed };
    } catch {
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
 * Tool call + `send` pass: Ollama 500/400 quirks, and (on the next /api/chat turn) sending
 * `tool_calls` in a shape the current Ollama build accepts. Only the **outgoing** request is
 * normalised; the in-memory transcript is unchanged.
 */
function normalizeToolCalls(calls: OllamaToolCall[] | undefined): OllamaToolCall[] | undefined {
  if (!calls?.length) return calls;
  return calls.map((tc) => ({
    ...tc,
    type: (tc.type ?? "function") as "function",
    function: {
      ...tc.function,
      arguments: normalizeToolArgumentsForWire(
        tc.function?.arguments as string | Record<string, unknown> | undefined,
      ),
    },
  }));
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
    const tool_calls = normalizeToolCalls(rest.tool_calls);
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
    if (c && c.length > MAX_ASSISTANT_TEXT) {
      c = `${c.slice(0, MAX_ASSISTANT_TEXT)}\n[… tool output truncated for model context …]`;
    }
    return { ...rest, content: c };
  }
  return rest;
}
