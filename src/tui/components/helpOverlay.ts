import React from "react";
import { Box, Text } from "ink";
import type { HelpContext, HelpTab } from "../types.js";
import { fitText } from "../utils/format.js";

interface HelpSection {
  title: string;
  rows: Array<[string, string]>;
}

const SUMMARY_SECTIONS: HelpSection[] = [
  {
    title: "Navigation",
    rows: [
      ["Tab", "Switch focus between panels (Accesses / Compromise / Saturation / Noise)"],
      ["↑/↓ PgUp/PgDn", "Move cursor in the active list"],
      ["Enter / d", "Open detail for selected row"]
    ]
  },
  {
    title: "Actions",
    rows: [
      ["f", "Filter global access log"],
      ["s", "Open sort menu"],
      ["t", "Top values (IPs, paths, UAs, params)"],
      ["a", "Ask OpenAI (requires OPENAI_API_KEY)"],
      ["e", "Export selection or current filtered result"],
      ["Space", "Toggle row selection"],
      ["A", "Select all visible rows"]
    ]
  },
  {
    title: "Exit",
    rows: [
      ["q / Esc", "Quit (with confirmation)"],
      ["h", "This help"]
    ]
  }
];

const INCIDENT_SECTIONS: HelpSection[] = [
  {
    title: "Navigation",
    rows: [
      ["↑/↓ PgUp/PgDn", "Scroll incident rows"],
      ["Enter / d", "Open request detail"]
    ]
  },
  {
    title: "Actions",
    rows: [
      ["t", "Top values for this incident"],
      ["Space", "Toggle row selection"],
      ["A", "Select all visible rows"],
      ["f", "Filter within incident"],
      ["s", "Open sort menu"],
      ["a", "Ask OpenAI about this incident"],
      ["e", "Export incident (waits for full hydration)"]
    ]
  },
  {
    title: "Exit",
    rows: [
      ["b / Esc", "Back to summary"],
      ["q", "Quit (with confirmation)"],
      ["h", "This help"]
    ]
  }
];

const TOPS_SECTIONS: HelpSection[] = [
  {
    title: "Navigation",
    rows: [
      ["Tab", "Switch panels (ips / paths / userAgents / params / paramValues)"],
      ["↑/↓", "Move cursor in active panel"]
    ]
  },
  {
    title: "Actions",
    rows: [
      ["Enter", "Apply selected value as filter"],
      ["a", "Ask OpenAI about top values"]
    ]
  },
  {
    title: "Exit",
    rows: [
      ["t / b / Esc", "Back to previous screen"],
      ["q", "Quit"],
      ["h", "This help"]
    ]
  }
];

const DETAIL_SECTIONS: HelpSection[] = [
  {
    title: "Navigation",
    rows: [["↑/↓ PgUp/PgDn", "Scroll request detail"]]
  },
  {
    title: "Exit",
    rows: [
      ["d / b / Esc", "Close detail"],
      ["q", "Quit"],
      ["h", "This help"]
    ]
  }
];

const ANSWER_SECTIONS: HelpSection[] = [
  {
    title: "Navigation",
    rows: [["↑/↓ PgUp/PgDn", "Scroll answer"]]
  },
  {
    title: "Exit",
    rows: [
      ["b / Esc", "Close answer"],
      ["q", "Quit"],
      ["h", "This help"]
    ]
  }
];

const EXPORT_MENU_SECTIONS: HelpSection[] = [
  {
    title: "Export menu",
    rows: [
      ["↑/↓", "Choose format (CSV / JSON / TSV)"],
      ["Enter", "Apply format"],
      ["Esc", "Cancel"],
      ["h", "This help"]
    ]
  }
];

const SORT_MENU_SECTIONS: HelpSection[] = [
  {
    title: "Sort menu",
    rows: [
      ["←/→ Tab", "Switch between field / direction / apply"],
      ["↑/↓", "Choose value"],
      ["Enter", "Apply sort"],
      ["Esc", "Cancel"],
      ["h", "This help"]
    ]
  }
];

const PROMPT_SECTIONS: HelpSection[] = [
  {
    title: "Active prompt (filter / question)",
    rows: [
      ["Type", "Edit prompt text"],
      ["←/→ Home/End", "Move cursor"],
      ["Backspace / Del", "Delete character"],
      ["Enter", "Submit"],
      ["Esc", "Cancel"],
      ["h", "(types literal h — close prompt first to open help)"]
    ]
  }
];

const CONTEXT_SECTIONS: Record<HelpContext, HelpSection[]> = {
  summary: SUMMARY_SECTIONS,
  incident: INCIDENT_SECTIONS,
  tops: TOPS_SECTIONS,
  detail: DETAIL_SECTIONS,
  answer: ANSWER_SECTIONS,
  exportMenu: EXPORT_MENU_SECTIONS,
  sortMenu: SORT_MENU_SECTIONS,
  prompt: PROMPT_SECTIONS
};

const CONTEXT_TITLE: Record<HelpContext, string> = {
  summary: "Keys — Summary",
  incident: "Keys — Incident",
  tops: "Keys — Top values",
  detail: "Keys — Request detail",
  answer: "Keys — OpenAI answer",
  exportMenu: "Keys — Export menu",
  sortMenu: "Keys — Sort menu",
  prompt: "Keys — Prompt"
};

const FILTER_SECTIONS: HelpSection[] = [
  {
    title: "Field operators",
    rows: [
      ["field:value", "contains (case-insensitive)"],
      ["field=value", "exact match"],
      ["field!=value", "not equal"],
      ["field>N  >=  <  <=", "numeric comparison (bytes, line, status)"],
      ["*", "wildcard"],
      ['"exact phrase"', "quoted value"]
    ]
  },
  {
    title: "Logic",
    rows: [
      ["AND", "implicit between terms"],
      ["OR  |", "alternative"],
      ["( ... )", "grouping"],
      ["!  NOT", "negation"]
    ]
  },
  {
    title: "Fields and aliases",
    rows: [
      ["status", "alias: st  — accepts status:2xx, 3xx, 4xx, 5xx"],
      ["ip / source", "alias: src"],
      ["method", "alias: mth"],
      ["path", "path without query string"],
      ["target", "alias: url — full path including query"],
      ["query", "alias: qs"],
      ["ua", "alias: userAgent"],
      ["bytes  time  line", "alias line: ln, lineNumber"],
      ["raw", "full raw log line"],
      ["param:<name>", "query parameter presence"],
      ["param:q=*select*", "value of parameter `q`"],
      ["param:*=*sleep*", "any parameter with that value"]
    ]
  },
  {
    title: "Examples",
    rows: [
      ["status:5xx AND path:/admin", "errors hitting admin"],
      ["ua:*bot* AND !ua:*Googlebot*", "bots that are not Googlebot"],
      ["param:q=*UNION* OR param:*=*../*", "SQLi or path traversal"],
      ["status>=400 AND method=POST", "failed POST requests"]
    ]
  }
];

interface RenderLine {
  text: string;
  color?: "cyan" | "gray" | "yellow";
  bold?: boolean;
}

function sectionsToLines(sections: HelpSection[], width: number): RenderLine[] {
  const keyCol = Math.min(22, Math.max(12, Math.floor(width * 0.32)));
  const lines: RenderLine[] = [];
  for (const section of sections) {
    if (lines.length > 0) lines.push({ text: "" });
    lines.push({ text: section.title, color: "cyan", bold: true });
    for (const [key, desc] of section.rows) {
      const padded = key.padEnd(keyCol);
      lines.push({ text: `  ${padded}${desc}` });
    }
  }
  return lines;
}

export function HelpOverlay({
  state,
  columns,
  rows
}: {
  state: { context: HelpContext; tab: HelpTab; scroll: number };
  columns: number;
  rows: number;
}): React.ReactElement {
  const width = Math.min(96, Math.max(50, columns - 4));
  const innerWidth = width - 6;
  const height = Math.min(Math.max(16, rows - 4), rows - 2);
  const top = Math.max(0, Math.floor((rows - height) / 2));
  const left = Math.max(0, Math.floor((columns - width) / 2));
  const blankLine = " ".repeat(innerWidth);

  const sections = state.tab === "keys" ? CONTEXT_SECTIONS[state.context] : FILTER_SECTIONS;
  const title = state.tab === "keys" ? CONTEXT_TITLE[state.context] : "Filter syntax";
  const allLines = sectionsToLines(sections, innerWidth);

  const headerRows = 4; // title + blank + tabs + blank
  const footerRows = 2; // blank + footer
  const bodyRows = Math.max(4, height - 2 - headerRows - footerRows);
  const maxScroll = Math.max(0, allLines.length - bodyRows);
  const scroll = Math.min(Math.max(0, state.scroll), maxScroll);
  const visible = allLines.slice(scroll, scroll + bodyRows);
  while (visible.length < bodyRows) visible.push({ text: "" });

  const tabsLabel = (label: string, active: boolean): React.ReactElement =>
    React.createElement(
      Text,
      {
        bold: active,
        color: active ? "black" : "gray",
        backgroundColor: active ? "yellow" : "black"
      },
      ` ${label} `
    );

  const scrollHint =
    maxScroll > 0 ? `  [${scroll + 1}-${Math.min(scroll + bodyRows, allLines.length)}/${allLines.length}]` : "";

  return React.createElement(
    Box,
    {
      position: "absolute",
      top,
      left,
      width,
      height,
      flexDirection: "column",
      borderStyle: "double",
      borderColor: "cyan",
      backgroundColor: "black",
      paddingX: 2,
      paddingY: 1
    },
    React.createElement(
      Text,
      { bold: true, color: "cyan", backgroundColor: "black", wrap: "truncate" },
      fitText(`${title}${scrollHint}`, innerWidth).padEnd(innerWidth)
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Box,
      { flexDirection: "row", gap: 2, backgroundColor: "black" },
      tabsLabel("Keys", state.tab === "keys"),
      tabsLabel("Filters", state.tab === "filters")
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    ...visible.map((line, index) =>
      React.createElement(
        Text,
        {
          key: `line-${index}`,
          color: line.color,
          bold: line.bold,
          backgroundColor: "black",
          wrap: "truncate"
        },
        (line.text || " ").padEnd(innerWidth).slice(0, innerWidth)
      )
    ),
    React.createElement(Text, { backgroundColor: "black" }, blankLine),
    React.createElement(
      Text,
      { color: "gray", backgroundColor: "black", wrap: "truncate" },
      fitText(
        "Tab / ←→ switch tab | ↑/↓ PgUp/PgDn scroll | h or Esc close",
        innerWidth
      ).padEnd(innerWidth)
    )
  );
}
