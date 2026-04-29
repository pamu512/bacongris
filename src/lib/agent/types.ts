/** Staged in the client with user text; content is merged for Ollama in `prepareForOllamaRequest`. */
export type ChatAttachment = {
  id: string;
  name: string;
  sizeBytes: number;
  /** UTF-8 text inlined for the model when the file is readable. */
  text?: string;
  /** When set, the file was not included as text. */
  omittedReason?: "too_large" | "binary" | "empty";
  mimeType?: string;
};

export type OllamaToolCall = {
  id?: string;
  type?: "function";
  function: {
    name: string;
    /** Ollama may send/return a JSON string or a parsed object; re-serialise to an object on the wire. */
    arguments?: string | Record<string, unknown>;
  };
};

export type OllamaMessage = {
  role: "system" | "user" | "assistant" | "tool";
  content?: string;
  /**
   * Long chain-of-thought or Ollama `thinking` kept for optional UI only; **never** sent to Ollama
   * (see `prepareForOllamaRequest`). Filled when the model emitted tool calls plus long internal prose.
   */
  thinking?: string;
  tool_calls?: OllamaToolCall[];
  /** Ollama / OpenAI-style tool result routing */
  tool_name?: string;
  name?: string;
  tool_call_id?: string;
  /** Client-only id for React keys and edit targeting; stripped before Ollama. */
  localId?: string;
  /** User-uploaded files (this turn). Merged into outbound `content`; not sent as a separate key. */
  attachments?: ChatAttachment[];
};

export type ApiRateLimitConfig = {
  requestsPerMinute: number;
  requestsPerDay: number;
  cacheTtlSecs?: number;
};

export type AppSettings = {
  /** Empty = default folder under app config (`…/BacongrisCTIAgent/workspace`). */
  workspacePath: string;
  ollamaBaseUrl: string;
  model: string;
  allowlistedRoots: string[];
  allowedExecutables: string[];
  executionTimeoutSecs: number;
  maxOutputBytes: number;
  /** When true, backend runs `run_command` inside Docker (no default network, cwd as `/workspace`). */
  useDockerSandbox: boolean;
  /** Image for Docker sandbox (e.g. `python:3.12-slim`). */
  dockerSandboxImage: string;
  /** CTI API keys (merged with `~/…/BacongrisCTIAgent/.api_keys.json` on the backend). */
  apiKeys?: Record<string, string>;
  /** Per-API rate limits (lowercase names, e.g. `virustotal`). */
  apiRateLimits?: Record<string, ApiRateLimitConfig>;
};
