import type { ChatAttachment } from "./agent/types";

/** Per-file cap before we refuse to inline (bytes). */
const MAX_BYTES_PER_FILE = 256 * 1024;
/** Total inlined character budget (after UTF-8 decode) for one user turn. */
const MAX_CHARS_TOTAL = 400_000;
/** If a single inlined text exceeds this, truncate with a note. */
const MAX_CHARS_PER_INLINE = 120_000;

const BINARY_MIME_PREFIXES = ["image/", "video/", "audio/"];
const BINARY_MIMES = new Set([
  "application/pdf",
  "application/zip",
  "application/gzip",
  "application/x-7z-compressed",
  "application/x-tar",
]);

function looksBinaryByMime(mime: string): boolean {
  const m = mime.toLowerCase().trim();
  if (!m) return false;
  if (BINARY_MIMES.has(m)) return true;
  return BINARY_MIME_PREFIXES.some((p) => m.startsWith(p));
}

/**
 * Heuristic: if too many U+FFFD replacement chars, treat as non-text.
 */
function isProbablyBinaryUtf8(s: string, byteLen: number): boolean {
  if (byteLen < 32) return false;
  const n = s.length;
  if (n < 1) return true;
  const bad = (s.match(/\uFFFD/g) ?? []).length;
  if (bad === 0) return false;
  if (bad / n > 0.02) return true;
  return false;
}

/**
 * Read one `File` into an attachment record (may omit text for size/binary).
 */
export async function fileToChatAttachment(f: File): Promise<ChatAttachment> {
  const id = crypto.randomUUID();
  const name = f.name || "untitled";
  const sizeBytes = f.size;
  const mime = f.type || undefined;

  if (sizeBytes === 0) {
    return { id, name, sizeBytes, omittedReason: "empty", mimeType: mime };
  }

  if (sizeBytes > MAX_BYTES_PER_FILE) {
    return { id, name, sizeBytes, omittedReason: "too_large", mimeType: mime };
  }

  if (mime && looksBinaryByMime(mime)) {
    return { id, name, sizeBytes, omittedReason: "binary", mimeType: mime };
  }

  const buf = await f.arrayBuffer();
  const fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let text: string;
  try {
    text = fatal.decode(buf);
  } catch {
    const lenient = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
    const t2 = lenient.decode(buf);
    if (isProbablyBinaryUtf8(t2, buf.byteLength)) {
      return { id, name, sizeBytes, omittedReason: "binary", mimeType: mime };
    }
    text = t2;
  }

  if (isProbablyBinaryUtf8(text, buf.byteLength)) {
    return { id, name, sizeBytes, omittedReason: "binary", mimeType: mime };
  }

  if (text.length > MAX_CHARS_PER_INLINE) {
    text = `${text.slice(0, MAX_CHARS_PER_INLINE)}\n\n[… truncated: file exceeded ${MAX_CHARS_PER_INLINE} characters; ask for a specific section if needed …]`;
  }
  return { id, name, sizeBytes, text, mimeType: mime };
}

export async function filesToChatAttachments(
  fileList: FileList | File[] | null,
): Promise<ChatAttachment[]> {
  if (fileList == null || (Array.isArray(fileList) && fileList.length === 0)) {
    return [];
  }
  const files = Array.isArray(fileList) ? fileList : Array.from(fileList);
  return Promise.all(files.map((f) => fileToChatAttachment(f)));
}

function formatOneAttachment(a: ChatAttachment): string {
  const header = `### Attached: ${a.name} (${a.sizeBytes} byte${a.sizeBytes === 1 ? "" : "s"})`;
  if (a.omittedReason === "too_large") {
    return `${header}\n_(not inlined: file over ${MAX_BYTES_PER_FILE} bytes. Save it under the workspace and use \`read_text_file\` or a smaller sample.)_`;
  }
  if (a.omittedReason === "binary" || a.omittedReason === "empty") {
    return `${header}\n_(not inlined: ${
      a.omittedReason === "empty" ? "empty file" : "treated as binary or non-text"
    }.)_`;
  }
  if (a.text == null) {
    return `${header}\n_(no text content.)_`;
  }
  return `${header}\n\`\`\`\n${a.text}\n\`\`\``;
}

/**
 * Text the model should see: optional user-typed line(s) + fenced file bodies.
 * Respects a total character budget so one turn cannot blow the context window.
 */
export function mergeUserMessageForModel(
  typedText: string,
  attachments?: ChatAttachment[] | undefined,
): string {
  const parts: string[] = [];
  const t = typedText?.trim() ?? "";
  if (t) parts.push(t);

  if (attachments?.length) {
    let used = parts.join("\n\n").length;
    for (const a of attachments) {
      const block = formatOneAttachment(a);
      if (used + block.length > MAX_CHARS_TOTAL) {
        parts.push(
          `[Further attachments omitted: inline budget ~${MAX_CHARS_TOTAL} characters reached.]`,
        );
        break;
      }
      parts.push(block);
      used += block.length + 2;
    }
  }
  return parts.join("\n\n");
}

/**
 * Shorter string for the **system** message routing hint (avoids duplicating huge pastes in the system prompt).
 */
export function systemHintForUserTurn(
  typedText: string,
  attachments: ChatAttachment[] | undefined,
): string {
  const t = typedText?.trim() ?? "";
  if (!attachments?.length) return t;
  if (!t) {
    return `User attached ${attachments.length} file(s); full text is in the user message below. Files: ${attachments.map((a) => a.name).join(", ")}`;
  }
  return `${t}\n\n(Also ${attachments.length} file attachment(s) below: ${attachments.map((a) => a.name).join(", ")}.)`;
}
