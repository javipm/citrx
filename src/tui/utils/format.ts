export function compactDateTime(timestamp: string): string {
  // Apache: "15/Jan/2024:14:30:00 +0000" → "15/Jan 14:30:00"
  const apache = timestamp.match(/^(\d{2}\/\w{3})\/\d{4}:(\d{2}:\d{2}:\d{2})/);
  if (apache) return `${apache[1]} ${apache[2]}`;
  // ISO: "2024-01-15T14:30:00..." → "01-15 14:30:00"
  const iso = timestamp.match(/^\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (iso) return `${iso[1]} ${iso[2]}`;
  return timestamp.slice(0, 15);
}

export function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }

  if (value < 1024 * 1024 * 1024) {
    return `${(value / 1024 / 1024).toFixed(1)} MiB`;
  }

  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

export function truncate(value: string, length: number): string {
  return value.length <= length ? value : `${value.slice(0, length - 1)}…`;
}

export function fitText(value: string, width: number): string {
  if (width <= 0) {
    return "";
  }

  const text = value.replace(/\s+/g, " ").trim();

  if (text.length <= width) {
    return text;
  }

  if (width <= 3) {
    return text.slice(0, width);
  }

  return `${text.slice(0, width - 3)}...`;
}

export function sanitizeFilePart(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.-]+/g, "_").replace(/^_+|_+$/g, "") || "unknown";
}
