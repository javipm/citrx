import React from "react";
import { Box, Text } from "ink";
import type { IncidentLogLine } from "../../analysis/types.js";

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
      React.createElement(
        Text,
        {
          key: `${scroll + index}:${value}`,
          color: value.startsWith("raw") || value.startsWith("        ") ? "gray" : undefined,
          wrap: "truncate"
        },
        value
      )
    )
  );
}
