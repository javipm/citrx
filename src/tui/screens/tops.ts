import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, useInput } from "ink";
import type { AnalyzeReport, Incident, IncidentLogLine, TopItem } from "../../analysis/types.js";
import {
  requestParamNames,
  requestParamValueLabels,
  userAgentLabel
} from "../../analysis/query-params.js";
import type { AccessLogIndexQueryCache } from "../../run/access-index.js";
import { readAccessLogIndexRows } from "../../run/access-index.js";
import type { CitrxRun } from "../../run/types.js";
import { createAccessLogLineFilter } from "../filter.js";
import type { TopScope, TopPanelKey, IncidentInsights } from "../types.js";
import { TOP_PANEL_KEYS } from "../types.js";
import { severityColor } from "../utils/colors.js";
import { fitText } from "../utils/format.js";

function accessQueryKey(filter: string, sortKey: string, sortDirection: string): string {
  return `${sortKey}:${sortDirection}:${filter}`;
}

function incrementMap(map: Map<string, number>, key: string): void {
  if (!key || key === "-") {
    return;
  }
  map.set(key, (map.get(key) ?? 0) + 1);
}

function topMapItems(map: Map<string, number>, limit: number): TopItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([value, count]) => ({ value, count }));
}

function addInsightLine(
  maps: {
    ips: Map<string, number>;
    paths: Map<string, number>;
    userAgents: Map<string, number>;
    params: Map<string, number>;
    paramValues: Map<string, number>;
  },
  line: IncidentLogLine
): void {
  incrementMap(maps.ips, line.ip);
  incrementMap(maps.paths, line.path);
  incrementMap(maps.userAgents, userAgentLabel(line.userAgent));

  for (const param of requestParamNames(line.target)) {
    incrementMap(maps.params, param);
  }

  for (const paramValue of requestParamValueLabels(line.target)) {
    incrementMap(maps.paramValues, paramValue);
  }
}

function topInsightMaps(maps: {
  ips: Map<string, number>;
  paths: Map<string, number>;
  userAgents: Map<string, number>;
  params: Map<string, number>;
  paramValues: Map<string, number>;
}): IncidentInsights {
  return {
    ips: topMapItems(maps.ips, 10),
    paths: topMapItems(maps.paths, 10),
    userAgents: topMapItems(maps.userAgents, 10),
    params: topMapItems(maps.params, 10),
    paramValues: topMapItems(maps.paramValues, 10)
  };
}

export function incidentInsights(lines: IncidentLogLine[]): IncidentInsights {
  const ips = new Map<string, number>();
  const paths = new Map<string, number>();
  const userAgents = new Map<string, number>();
  const params = new Map<string, number>();
  const paramValues = new Map<string, number>();

  for (const line of lines) {
    addInsightLine({ ips, paths, userAgents, params, paramValues }, line);
  }

  return topInsightMaps({ ips, paths, userAgents, params, paramValues });
}

export async function incidentInsightsFromAccessIndex(
  run: CitrxRun,
  accessQueryCache: AccessLogIndexQueryCache,
  filter: string
): Promise<{
  insights: IncidentInsights;
  count: number;
}> {
  if (!filter) {
    return {
      insights: reportInsights(run.report),
      count: run.report.accessLog.totalLines
    };
  }

  const maps = {
    ips: new Map<string, number>(),
    paths: new Map<string, number>(),
    userAgents: new Map<string, number>(),
    params: new Map<string, number>(),
    paramValues: new Map<string, number>()
  };
  const query = await accessQueryCache.getOrBuild(
    run.accessIndex,
    accessQueryKey(filter, "timestamp", "desc"),
    {
      filter: createAccessLogLineFilter(filter),
      sortKey: "timestamp",
      sortDirection: "desc"
    }
  );

  for (const line of readAccessLogIndexRows(run.accessIndex, query.rows)) {
    addInsightLine(maps, line);
  }

  return {
    insights: topInsightMaps(maps),
    count: query.total
  };
}

export function filteredTopLines(lines: IncidentLogLine[], filter: string): IncidentLogLine[] {
  if (!filter) {
    return lines;
  }

  const matches = createAccessLogLineFilter(filter);
  return lines.filter((line) => matches(line));
}

export function emptyIncidentInsights(): IncidentInsights {
  return {
    ips: [],
    paths: [],
    userAgents: [],
    params: [],
    paramValues: []
  };
}

export function reportInsights(report: AnalyzeReport): IncidentInsights {
  return {
    ips: report.topIps.slice(0, 10),
    paths: report.topPaths.slice(0, 10),
    userAgents: report.topUserAgents.slice(0, 10),
    params: report.topParams.slice(0, 10),
    paramValues: report.topParamValues.slice(0, 10)
  };
}

export function selectedTopValue(
  insights: IncidentInsights,
  panel: TopPanelKey,
  selectedIndex: number
): TopItem | undefined {
  const items = insights[panel];
  return items[Math.max(0, Math.min(selectedIndex, Math.max(0, items.length - 1)))];
}

export function topItemFilter(panel: TopPanelKey, value: string): string {
  switch (panel) {
    case "ips":
      return `ip=${filterValue(value)}`;
    case "paths":
      return `path=${filterValue(value)}`;
    case "userAgents":
      return `ua:${filterValue(value)}`;
    case "params":
      return `param=${filterValue(value)}`;
    case "paramValues":
      return `param:${filterValue(value)}`;
  }
}

function filterValue(value: string): string {
  return `"${value.replace(/["\\]/g, (char) => `\\${char}`)}"`;
}

export function currentTopContext(
  report: AnalyzeReport,
  scope: TopScope,
  incident: Incident | undefined,
  filter: string,
  focus: TopPanelKey,
  selectedIndexes: Record<TopPanelKey, number>
): string {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);
  const insights =
    scope === "summary"
      ? {
          ips: report.topIps,
          paths: report.topPaths,
          userAgents: report.topUserAgents,
          params: report.topParams,
          paramValues: report.topParamValues
        }
      : incidentInsights(filteredTopLines(matchSet?.lines ?? [], filter));
  const selected = selectedTopValue(insights, focus, selectedIndexes[focus]);
  const lines = [
    `scope=${scope}`,
    filter ? `filter=${filter}` : undefined,
    incident ? `incident=${incident.id}` : undefined,
    selected
      ? `selectedPanel=${focus} selected=${selected.value} count=${selected.count}`
      : `selectedPanel=${focus}`,
    `topIps=${topItemsForContext(insights.ips)}`,
    `topPaths=${topItemsForContext(insights.paths)}`,
    `topUserAgents=${topItemsForContext(insights.userAgents)}`,
    `topParams=${topItemsForContext(insights.params)}`,
    `topParamValues=${topItemsForContext(insights.paramValues)}`
  ].filter((line): line is string => Boolean(line));

  return lines.join("\n");
}

function topItemsForContext(items: TopItem[]): string {
  return (
    items
      .slice(0, 10)
      .map((item) => `${item.value}:${item.count}`)
      .join(" | ") || "none"
  );
}

export function nextTopPanel(value: TopPanelKey): TopPanelKey {
  const index = TOP_PANEL_KEYS.indexOf(value);
  return TOP_PANEL_KEYS[(index + 1) % TOP_PANEL_KEYS.length] ?? "ips";
}

function TopListPanel({
  title,
  panelKey,
  items,
  width,
  active,
  selectedIndex,
  loading = false
}: {
  title: string;
  panelKey: TopPanelKey;
  items: TopItem[];
  width: number;
  active: boolean;
  selectedIndex: number;
  loading?: boolean;
}) {
  const safeSelectedIndex = Math.max(0, Math.min(selectedIndex, Math.max(0, items.length - 1)));

  return React.createElement(
    Box,
    {
      flexDirection: "column",
      borderStyle: "single",
      borderColor: active ? "cyan" : undefined,
      paddingX: 1,
      width
    },
    React.createElement(
      Text,
      { bold: true, color: active ? "cyan" : undefined, wrap: "truncate" },
      fitText(`${active ? "> " : "  "}${title}`, width - 2)
    ),
    ...(loading
      ? [
          React.createElement(
            Text,
            { key: "loading", color: "yellow" },
            fitText("computing...", width - 2)
          )
        ]
      : items.length > 0
        ? items.map((item, index) =>
            React.createElement(
              Text,
              {
                key: `${panelKey}:${item.value}`,
                color: active && index === safeSelectedIndex ? "black" : undefined,
                backgroundColor: active && index === safeSelectedIndex ? "white" : undefined,
                wrap: "truncate"
              },
              fitText(`${String(item.count).padStart(5)}  ${item.value}`, width - 2)
            )
          )
        : [React.createElement(Text, { key: "empty", color: "gray" }, "none")])
  );
}

export function TopValuesScreen({
  run,
  accessQueryCache,
  report,
  incident,
  scope,
  filter,
  focus,
  selectedIndexes,
  onApplyFilter,
  columns
}: {
  run: CitrxRun;
  accessQueryCache: AccessLogIndexQueryCache;
  report: AnalyzeReport;
  incident: Incident | undefined;
  scope: TopScope;
  filter: string;
  focus: TopPanelKey;
  selectedIndexes: Record<TopPanelKey, number>;
  onApplyFilter: (filter: string) => void;
  columns: number;
}): React.ReactElement {
  const matchSet = report.incidentMatches.find((item) => item.incidentId === incident?.id);
  const incidentTopValues = useMemo(
    () => incidentInsights(filteredTopLines(matchSet?.lines ?? [], filter)),
    [filter, matchSet]
  );
  const [summaryTopValues, setSummaryTopValues] = useState<{
    insights: IncidentInsights;
    count: number;
  }>();
  const [loading, setLoading] = useState(false);
  const panelWidth = Math.max(30, Math.floor((columns - 7) / 2));
  const headerWidth = Math.max(40, columns - 10);

  useEffect(() => {
    if (scope !== "summary") {
      setLoading(false);
      return;
    }

    let cancelled = false;
    const needsSummaryBuild = Boolean(filter);

    if (needsSummaryBuild) {
      setLoading(true);
      setSummaryTopValues(undefined);
    }

    void incidentInsightsFromAccessIndex(run, accessQueryCache, filter)
      .then((value) => {
        if (!cancelled) {
          setSummaryTopValues(value);
          setLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSummaryTopValues(undefined);
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [accessQueryCache, filter, run, scope]);

  const insights =
    scope === "summary"
      ? filter
        ? (summaryTopValues?.insights ?? emptyIncidentInsights())
        : reportInsights(report)
      : incidentTopValues;
  const sourceCount =
    scope === "summary"
      ? filter
        ? (summaryTopValues?.count ?? 0)
        : report.accessLog.totalLines
      : (matchSet?.totalMatches ?? 0);
  const selectedTopItem = selectedTopValue(insights, focus, selectedIndexes[focus]);

  useInput((_inputValue, key) => {
    if (!key.return || !selectedTopItem) {
      return;
    }

    onApplyFilter(topItemFilter(focus, selectedTopItem.value));
  });

  if (scope === "incident" && !incident) {
    return React.createElement(Text, null, "No incident selected");
  }

  const title =
    scope === "summary" ? "Global top values" : `Top values for ${incident?.id ?? "incident"}`;
  const subtitle =
    scope === "summary"
      ? `${loading ? "computing..." : "computed"} from ${sourceCount}/${report.accessLog.totalLines} parsed access-log rows${filter ? ` | filter=${filter}` : ""}`
      : `computed from ${sourceCount} related requests${filter ? ` | filter=${filter}` : ""}`;

  return React.createElement(
    Box,
    { flexDirection: "column", flexGrow: 1 },
    React.createElement(
      Box,
      { flexDirection: "column", borderStyle: "single", paddingX: 1 },
      React.createElement(
        Text,
        {
          bold: true,
          color: scope === "summary" ? "cyan" : severityColor(incident?.severity ?? "info"),
          wrap: "truncate"
        },
        fitText(title, headerWidth)
      ),
      React.createElement(Text, { color: "gray", wrap: "truncate" }, fitText(subtitle, headerWidth))
    ),
    React.createElement(
      Box,
      { flexDirection: "column", flexGrow: 1 },
      React.createElement(
        Box,
        { flexDirection: "row", gap: 1, flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top IPs",
          panelKey: "ips",
          items: insights.ips,
          width: panelWidth,
          active: focus === "ips",
          selectedIndex: selectedIndexes.ips,
          loading
        }),
        React.createElement(TopListPanel, {
          title: "Top paths",
          panelKey: "paths",
          items: insights.paths,
          width: panelWidth,
          active: focus === "paths",
          selectedIndex: selectedIndexes.paths,
          loading
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "row", gap: 1, flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top user agents",
          panelKey: "userAgents",
          items: insights.userAgents,
          width: panelWidth,
          active: focus === "userAgents",
          selectedIndex: selectedIndexes.userAgents,
          loading
        }),
        React.createElement(TopListPanel, {
          title: "Top query params",
          panelKey: "params",
          items: insights.params,
          width: panelWidth,
          active: focus === "params",
          selectedIndex: selectedIndexes.params,
          loading
        })
      ),
      React.createElement(
        Box,
        { flexDirection: "row", flexGrow: 1 },
        React.createElement(TopListPanel, {
          title: "Top query param values",
          panelKey: "paramValues",
          items: insights.paramValues,
          width: panelWidth,
          active: focus === "paramValues",
          selectedIndex: selectedIndexes.paramValues,
          loading
        })
      )
    )
  );
}
