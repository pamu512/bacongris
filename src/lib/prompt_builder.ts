/**
 * System prompt assembly for Ollama. Primary implementation and CTI copy live in
 * {@link "./agent/systemPrompt"}; this module is a stable import path ("prompt builder").
 */
export {
  buildCtiSystemMessageContent,
  CTI_SYSTEM_IDENTITY,
  CTI_SYSTEM_KNOWLEDGE,
  CTI_SYSTEM_PROMPT,
  type CtiSystemMessageOptions,
} from "./agent/systemPrompt";

export {
  OllamaClient,
  OLLAMA_STALE_INTELLIGENCE_PREFIX,
  preFlightCheck,
} from "./agent/OllamaClient";
export type { PreFlightResult } from "./agent/OllamaClient";
