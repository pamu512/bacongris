import { getFreshnessContext, isLocalIntelligenceStale } from "../ContextIntegrator";

const STALE_WARNING = "⚠️ Local Intelligence is Stale";

export type PreFlightResult = {
  /** True when no sync or newest maintenance success is older than the window. */
  stale: boolean;
  /** Short line to prepend to the model’s final assistant message when `stale` is true. */
  warningLine: string | undefined;
  /** Freshness summary (last 3 syncs); read for side effect / host logging. */
  freshnessSummary: string;
};

/**
 * Runs before each Ollama user turn: loads maintenance-driven freshness and decides whether
 * local intel is older than 24h (configurable).
 */
export async function preFlightCheck(
  maxAgeHours: number = 24,
): Promise<PreFlightResult> {
  const [freshnessSummary, stale] = await Promise.all([
    getFreshnessContext(),
    isLocalIntelligenceStale(maxAgeHours),
  ]);
  return {
    stale,
    warningLine: stale ? STALE_WARNING : undefined,
    freshnessSummary,
  };
}

export const OLLAMA_STALE_INTELLIGENCE_PREFIX = STALE_WARNING;

export const OllamaClient = {
  preFlightCheck,
} as const;
