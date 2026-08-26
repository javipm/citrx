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

const DECODE_PASSES = 3;
const PAIR_PATTERN = /([^=?&\s"]+)=([^&\s"]*)/g;

export function decodeRepeated(value: string): string {
  let current = value.replace(/\+/g, " ");

  for (let pass = 0; pass < DECODE_PASSES; pass += 1) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) {
        break;
      }
      current = next;
    } catch {
      break;
    }
  }

  return current;
}

export function isSensitiveParamName(name: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(decodeRepeated(name));
}

/**
 * Replaces `key=value` pairs whose key looks sensitive with `key=[REDACTED]`.
 * Keys are matched after repeated percent-decoding so `%74oken` and `%2574oken`
 * still redact. Value matching stops at `&`, whitespace, or `"`.
 */
export function redactSecretPairs(text: string): string {
  return text.replace(PAIR_PATTERN, (match, key: string) => {
    if (isSensitiveParamName(key)) {
      return `${key}=[REDACTED]`;
    }

    return match;
  });
}
