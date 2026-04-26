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

export type AppSettings = {
  /** Empty = default folder under app config (`…/BacongrisCTIAgent/workspace`). */
  workspacePath: string;
  ollamaBaseUrl: string;
  model: string;
  allowlistedRoots: string[];
  allowedExecutables: string[];
  executionTimeoutSecs: number;
  maxOutputBytes: number;
};
