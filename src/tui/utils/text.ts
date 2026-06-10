import type { IncidentLogLine } from "../../analysis/types.js";

export function wrapHard(value: string, width: number): string[] {
  const chunks: string[] = [];
  let remaining = value || "-";

  while (remaining.length > width) {
    chunks.push(remaining.slice(0, width));
    remaining = remaining.slice(width);
  }

  chunks.push(remaining);
  return chunks;
}

export function wrapWords(value: string, width: number): string[] {
  if (value.length <= width) {
    return [value];
  }

  const chunks: string[] = [];
  let current = "";

  for (const word of value.split(/\s+/)) {
    if (word.length > width) {
      if (current) {
        chunks.push(current);
        current = "";
      }
      chunks.push(...wrapHard(word, width));
      continue;
    }

    const next = current ? `${current} ${word}` : word;
    if (next.length > width) {
      chunks.push(current);
      current = word;
    } else {
      current = next;
    }
  }

  if (current) {
    chunks.push(current);
  }

  return chunks.length > 0 ? chunks : [value];
}

export function requestDetailLines(line: IncidentLogLine, width: number): string[] {
  return [
    ...wrapDetailField("source", line.source, width),
    ...wrapDetailField("time", line.timestamp, width),
    ...wrapDetailField("ip", line.ip, width),
    ...wrapDetailField(
      "method",
      `${line.method} | status=${line.status} | bytes=${line.bytes ?? "-"}`,
      width
    ),
    ...wrapDetailField("path", line.path, width),
    ...wrapDetailField("target", line.target, width),
    ...wrapDetailField("ua", line.userAgent ?? "-", width),
    ...wrapDetailField("raw", line.raw, width)
  ];
}

function wrapDetailField(label: string, value: string, width: number): string[] {
  const labelWidth = 8;
  const contentWidth = Math.max(20, width - labelWidth - 1);
  const chunks = wrapHard(value, contentWidth);

  return chunks.map(
    (chunk, index) => `${index === 0 ? label.padEnd(labelWidth) : " ".repeat(labelWidth)} ${chunk}`
  );
}
