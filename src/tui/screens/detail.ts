import React from "react";
import { Box, Text } from "ink";
import type { IncidentLogLine } from "../../analysis/types.js";
import type { OpenAiAnswerState, RenderLine } from "../types.js";

export function RequestDetailScreen({
  line,
  visibleLines,
  scroll,
  totalLines
}: {
  line: IncidentLogLine;
  visibleLines: string[];
  scroll: number;
  totalLines: number;
}): React.ReactElement {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "double", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Text,
      { bold: true, color: "cyan", wrap: "truncate" },
      `Request detail | line=${line.lineNumber} | ${scroll + 1}-${Math.min(scroll + visibleLines.length, totalLines)}/${totalLines}`
    ),
    ...visibleLines.map((value, index) =>
      React.createElement(Text, { key: `${scroll + index}:${value}`, color: value.startsWith("raw") || value.startsWith("        ") ? "gray" : undefined, wrap: "truncate" }, value)
    )
  );
}

export function OpenAiAnswerScreen({
  answer,
  visibleLines,
  scroll,
  totalLines
}: {
  answer: OpenAiAnswerState;
  visibleLines: RenderLine[];
  scroll: number;
  totalLines: number;
}): React.ReactElement {
  return React.createElement(
    Box,
    { flexDirection: "column", borderStyle: "double", paddingX: 1, flexGrow: 1 },
    React.createElement(
      Text,
      { bold: true, color: "cyan", wrap: "truncate" },
      `${answer.title} | ${scroll + 1}-${Math.min(scroll + visibleLines.length, totalLines)}/${totalLines}`
    ),
    React.createElement(Text, { color: "gray", wrap: "truncate" }, answer.meta),
    ...visibleLines.map((value, index) =>
      React.createElement(
        Text,
        {
          key: `${scroll + index}:${value.text}`,
          color: value.color,
          bold: value.bold,
          wrap: "truncate"
        },
        value.text
      )
    )
  );
}
