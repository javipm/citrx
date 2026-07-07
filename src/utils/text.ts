/**
 * Truncates display strings to a fixed length, appending an ellipsis.
 *
 * Used by report renderers (terminal/markdown/html) to keep top-value tables
 * readable. Aggregation/filtering must always use the full untruncated value;
 * only rendering should call this.
 */
export function truncateForDisplay(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  if (maxLength <= 1) {
    return value.slice(0, maxLength);
  }

  return `${value.slice(0, maxLength - 1)}…`;
}
