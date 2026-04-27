export type OllamaToolCall = {
  id?: string;
  function: {
    name: string;
    /** Ollama may send a JSON string or a parsed object. */
    arguments?: string | Record<string, unknown>;
  };
};

export type OllamaMessage = {
  role: "system" | "user" | "assistant" | "tool";
  content?: string;
  tool_calls?: OllamaToolCall[];
  /** Ollama / OpenAI-style tool result routing */
  tool_name?: string;
  name?: string;
  tool_call_id?: string;
  /** Client-only id for React keys and edit targeting; stripped before Ollama. */
  localId?: string;
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
