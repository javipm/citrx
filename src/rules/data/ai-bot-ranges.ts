import { OPENAI_CHATGPT_USER_RANGES } from "./openai-chatgpt-user-ranges.js";
import { OPENAI_GPTBOT_RANGES } from "./openai-gptbot-ranges.js";
import { OPENAI_SEARCHBOT_RANGES } from "./openai-searchbot-ranges.js";
import { PERPLEXITY_USER_RANGES } from "./perplexity-user-ranges.js";
import { PERPLEXITYBOT_RANGES } from "./perplexitybot-ranges.js";

interface RangeSnapshot {
  readonly ipv4: readonly string[];
  readonly ipv6: readonly string[];
}

/**
 * AI crawlers whose operators publish the IP ranges they crawl from, keyed by
 * the `AI_BOT_PATTERNS` name. Only these can be checked: for every other AI
 * user-agent the name is self-declared and unprovable from an access log, so
 * citrx marks it unverifiable rather than implying it validated anything.
 *
 * Refresh the snapshots with `pnpm run update-bot-ranges`.
 */
export const AI_BOT_RANGES: ReadonlyMap<string, RangeSnapshot> = new Map<string, RangeSnapshot>([
  ["GPTBot", OPENAI_GPTBOT_RANGES],
  ["OAI-SearchBot", OPENAI_SEARCHBOT_RANGES],
  ["PerplexityBot", PERPLEXITYBOT_RANGES]
]);

// Deliberately not verified: `ChatGPT-User`, `ChatGPT Agent` and
// `Perplexity-User` fetch on behalf of a person rather than crawling, and egress
// from a wider, faster-changing pool than the published crawler lists cover.
// Checking them against those lists reported legitimate Azure-hosted traffic as
// forged, so they are treated as unverifiable like every other AI user-agent.
void OPENAI_CHATGPT_USER_RANGES;
void PERPLEXITY_USER_RANGES;
