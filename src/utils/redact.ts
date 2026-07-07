/**
 * Single source of truth for detecting and redacting sensitive request data
 * (query params, header-like key=value pairs) across the codebase.
 *
 * `_token` is redundant with `token` (both match) but kept explicit for
 * readability/documentation of intent (e.g. Symfony/Laravel `_token` fields).
 */
// Intentional substring match (no \b word boundaries): covers variants like api_key or access_token,
// at the cost of possible over-redaction (e.g., "monkey" contains "key"). Legacy behavior from prior implementations.
export const SENSITIVE_KEY_PATTERN =
  /token|_token|sid|session|password|passwd|key|secret|jwt|auth|authorization|credential/i;

export function isSensitiveParamName(name: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(name);
}

const SENSITIVE_PAIR_PATTERN = new RegExp(
  `(${SENSITIVE_KEY_PATTERN.source})=([^&\\s"]+)`,
  "gi"
);

/**
 * Replaces `key=value` pairs whose key looks sensitive with `key=[REDACTED]`.
 * Value matching stops at `&`, whitespace, or `"` (does not consume quotes).
 */
export function redactSecretPairs(text: string): string {
  return text.replace(SENSITIVE_PAIR_PATTERN, "$1=[REDACTED]");
}
