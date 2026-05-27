import type { IncidentLogLine } from "../../analysis/types.js";
import type { RenderLine } from "../types.js";
import { fitText } from "./format.js";

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

export function stripMarkdownInline(value: string): string {
  return value
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1");
}

export function renderMarkdownAnswer(value: string, width: number): RenderLine[] {
  const contentWidth = Math.max(20, width);
  const lines = value.replace(/\r\n/g, "\n").split("\n");
  const rendered: RenderLine[] = [];
  let inCodeBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      rendered.push({ text: inCodeBlock ? "  ┌─ code" : "  └─", color: "gray" });
      continue;
    }

    if (line.trim().length === 0) {
      rendered.push({ text: "" });
      continue;
    }

    if (inCodeBlock) {
      for (const chunk of wrapHard(line, Math.max(20, contentWidth - 6))) {
        rendered.push({ text: `  │ ${stripMarkdownInline(chunk)}`, color: "green" });
      }
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      if (rendered.length > 0 && rendered[rendered.length - 1]?.text !== "") {
        rendered.push({ text: "" });
      }
      rendered.push({
        text: `▶ ${fitText(stripMarkdownInline(heading[2] ?? ""), contentWidth - 2)}`,
        color: "cyan",
        bold: true
      });
      continue;
    }

    const bullet = line.match(/^(\s*)[-*]\s+(.+)$/);
    if (bullet) {
      const indent = " ".repeat(Math.min(6, Math.floor((bullet[1]?.length ?? 0) / 2) * 2));
      const prefix = `${indent}• `;
      for (const [index, chunk] of wrapWords(
        stripMarkdownInline(bullet[2] ?? ""),
        Math.max(20, contentWidth - prefix.length)
      ).entries()) {
        rendered.push({
          text: `${index === 0 ? prefix : " ".repeat(prefix.length)}${chunk}`,
          color: index === 0 ? undefined : "gray"
        });
      }
      continue;
    }

    const ordered = line.match(/^(\s*)(\d+)\.\s+(.+)$/);
    if (ordered) {
      const indent = " ".repeat(Math.min(6, Math.floor((ordered[1]?.length ?? 0) / 2) * 2));
      const prefix = `${indent}${ordered[2]}. `;
      for (const [index, chunk] of wrapWords(
        stripMarkdownInline(ordered[3] ?? ""),
        Math.max(20, contentWidth - prefix.length)
      ).entries()) {
        rendered.push({
          text: `${index === 0 ? prefix : " ".repeat(prefix.length)}${chunk}`,
          color: index === 0 ? undefined : "gray"
        });
      }
      continue;
    }

    for (const chunk of wrapWords(stripMarkdownInline(line), contentWidth)) {
      rendered.push({ text: chunk });
    }
  }

  return rendered.length > 0 ? rendered : [{ text: "No answer returned." }];
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
