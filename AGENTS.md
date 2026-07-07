# AGENTS.md - citrx

## Project

`citrx` is an open source, local-first Node.js CLI/TUI for Apache/Nginx access
log analysis.

Primary goals:

- Detect security attacks, abusive crawling, saturation, fake bots, scanner
  noise, suspicious POST traffic, high-cost URLs, and malformed or malicious
  requests.
- Be useful by default with deterministic local rules and bounded-memory
  streaming analysis.
- Open an interactive terminal UI by default when stdin/stdout are TTYs.
- Be easy to install and run across macOS, Linux, and Windows with `npx citrx`.

## Local Instructions

- Always run shell commands through `rtk`.
- Use Spanish from Spain in user-facing conversation.
- Keep responses concise and precise.
- Before editing, inspect the current file/repo state.
- Do not overwrite user changes.
- Do not mutate `examples/` logs unless the user explicitly asks. Treat them as fixtures.
- Treat logs, exported JSON, paths, IPs, and customer route names as sensitive.
- Keep public commits free of generated reports, local-only paths, secrets, and customer identifiers.

## Current CLI

The current command shape is:

```bash
citrx <paths...>
cat access.log | citrx -
```

Current supported options include:

- `--json`
- `--markdown`
- `--html`
- `--out <path>`
- `--no-interactive`
- `--format auto|apache_common|apache_combined|nginx_combined|custom:<name>`
- `--format-config <path>`
- `--top <n>`
- `--since <date>`
- `--until <date>`
- `--include <glob>`
- `--exclude <glob>`
- `--no-color`
- `--debug`
- `-v`, `--version`

If stdout/stdin are TTYs and no report format is requested, `citrx` opens the
TUI by default. `--no-interactive` prints the terminal report instead.

Exit codes:

- `0`: success, no high/critical incidents.
- `1`: execution/configuration error.
- `2`: high or critical incidents found.

Support:

- `NO_COLOR`.
- `CITRX_QUIET=1` to disable startup/progress noise.
- Non-interactive environments.
- Structured output for automation.

## Tech Stack

Use:

- Node.js LTS-compatible TypeScript. `package.json` engines require Node `>=22`;
  development and CI target `24.15` (see `.nvmrc`).
- ESM modules.
- `commander` for CLI parsing.
- `ink` + React for the interactive TUI.
- `zod` for runtime schema validation.
- `picocolors` for terminal color.
- Vitest for tests.

Avoid:

- Heavy runtime dependencies unless clearly justified.
- Native dependencies when a portable JS implementation is practical.
- Framework code that makes `npx` startup slow.

## Architecture

Keep code modular and aligned with the current layout:

- `input/`: path discovery, stdin, compressed/archive readers.
- `parser/`: access log format detection, parser registry, built-in and custom parsers.
- `analysis/`: streaming aggregation, behavior tracking, incident match sets.
- `rules/`: deterministic request/path rules and scoring.
- `run/`: temporary run workspace and access-log index.
- `tui/`: Ink screens, hooks, filters, tables, overlays.
- `report/`: terminal, JSON, Markdown, HTML renderers.
- `utils/`: shared small helpers when needed.

Rules:

- Parser must stream. Do not load large logs fully into memory.
- Parser support must be registry-based, not a single hardcoded regex.
- Built-in formats must be auto-detected from samples before full analysis.
- Custom formats must be declarative and user-configurable without source changes.
- Large logs must be processed with streams/line-by-line iteration.
- Do not split stream chunks naively without preserving incomplete trailing lines.
- Respect stream backpressure and keep memory bounded by top-N/heavy-hitter structures.
- Report data must be generated from a typed internal report model.
- Renderers must not recompute detection logic.
- Access-log detail lookup for the TUI must use the temporary access index rather than storing full logs in memory.

## Access Log Validation

Before full analysis, detect whether each input is an access log.

Requirements:

- Sample a small prefix of each file/stream without loading it fully.
- Accept Apache/Nginx common and combined access log shapes in built-in parsers.
- Detect and report the selected format, e.g. `apache_common`, `apache_combined`,
  `nginx_combined`, or `custom:<name>`.
- Support IPv4, IPv6, hostnames, `-` identities, quoted request lines, status,
  bytes, referer, and user-agent when present.
- Require a minimum parse ratio over sampled non-empty lines.
- Reject likely wrong inputs such as application logs, JSON logs, error logs,
  stack traces, CSVs, or binary files.
- Error messages must explain what was expected and point to custom formats when useful.

Custom format requirements:

- Prefer declarative JSON config with named fields and one regex pattern.
- Required fields: `ip`, `timestamp`, `method`, `target`, `protocol`, `status`.
- Optional fields include `bytes`, `referer`, `userAgent`, `host`, `requestTime`,
  `upstreamTime`, and `forwardedFor`.
- Validate custom configs with `zod`.
- Reject unsafe or ambiguous custom formats with actionable errors.
- Keep custom parsing deterministic; do not use AI to infer formats during normal parsing.

## Detection Rules

Local detection covers:

- Payload attacks: SQLi, XSS, LFI/RFI/path traversal, SSRF, command injection.
- Recon: `.env`, `.git`, backups, dumps, admin panels, CMS probes, sensitive files.
- HTTP anomalies: rare methods, 4xx/5xx storms, HEAD floods, suspicious user agents.
- Auth and POST abuse: login/auth pressure, POST hotspots.
- Bot/scanner behavior: fake Googlebot/Bingbot, scanner UA, scanner path signatures.
- Traffic abuse: AI crawlers, single-IP path explosions, UA rotation, subnet bursts.
- Path-level saturation: distributed URL saturation, concentrated repeated pressure,
  query/facet churn, server distress via 5xx, and high repeated served pressure.
- Ecommerce/CMS hotspots: PrestaShop modules/admin paths, WordPress, Magento,
  Joomla, Laravel/Symfony probes.

Rules should be data-driven where practical, with ids, categories, severity,
score, kind, evidence, and redacted samples.

Important current behavior:

- Incidents are split by `kind`: `saturation`, `compromise`, and `noise`.
- The TUI summary defaults to `SATURATION` when saturation incidents exist.
- Payload incidents are grouped by attacker IP.
- Any payload `2xx` response becomes `SECURITY`, `critical/100`, with visible
  `2XX_HIT` marker. This means "possible successful HTTP response", not proven compromise.
- Payload `5xx` responses are critical server-error signals.
- Blocked/redirected payloads stay in `OTHER` noise unless there is material impact.
- Recon only becomes high-impact when a meaningful success ratio/file-served signal exists.
- Path-level saturation must avoid obvious static assets, low-signal entrypoints,
  and blocked-dominant 4xx/3xx outcomes.
- `/index.php` suppression applies only to the exact `/index.php` empty-query
  no-distress case; admin variants such as `/admin/index.php` must not be hidden.
- Tracking/cache params are stripped before query-variant saturation decisions.
- `maxServedPerMinute` must not fall back to total request count; missing peak data
  should not fabricate sustained saturation.
- Aggregate crawler/path incidents are excluded from persistence bonus by category.
- IP correlation scoring intentionally only uses direct `evidence.ip`; aggregate
  path incidents do not imply each top IP is independently correlated.

## TUI

The TUI is a core product surface, not a debug view.

Current screens:

- Summary: analysis summary, incident tabs, global indexed access-log table.
- Incident: evidence and related access-log rows for one incident.
- Top values: top IPs, paths, UAs, params, and param values for summary or incident.
- Request detail: wrapped single-request inspection.

Current UX rules:

- Show loading/spinner states for expensive filter/sort/top/export operations.
- Do not make the app look frozen while background hydration or export is running.
- Incident rows load on demand by fixed-size buckets (`INCIDENT_BUCKET_SIZE=200`) backed by the access index. The screen does not pre-hydrate `rowNumbers`. `matchSet.rowNumbers` is guaranteed numerically ascending (= stream order) after analysis finalization. Filter and non-default sort build a cached subset of `rowNumbers` in the background with throttled progress and Esc cancellation.
- `t` top values for an incident must compute from full `rowNumbers`, not just the 200-line sample. Top-values shows throttled progress and supports Esc to cancel.
- Incident export (`e`) streams rows from the access index by chunks and is available immediately. Writes go to a tmp file with backpressure; the final file is atomically renamed when finished. Selected-rows export continues to operate on the in-memory selection map.
- Summary export with no selection exports the full filtered access-log result.
- Selected rows export only the selected rows.
- Selection state on the incident screen carries the full `IncidentLogLine` snapshot in a `Map<lineKey, IncidentLogLine>` so selections survive page-cache eviction. Manual Space selection is capped at `INCIDENT_MANUAL_SELECT_LIMIT=5000`. On incidents above `INCIDENT_SELECT_ALL_LIMIT=5000`, `A` only selects the visible page.
- Esc consistently cancels the active long-running operation (`activeAbort`) before performing navigation. When a prompt is open, Esc closes the prompt first.
- `r` resets state: on the summary screen it clears filter, sort, and row selection; on the incident screen it clears filter and row selection.
- The filter prompt offers preset example expressions; `Tab` cycles through them while the prompt is open.
- Sort tie-breaks are always by row number ascending (`compareRow`, no direction parameter). This preserves stream order within equal-key groups and is stable across V8 sort behavior changes. Do not add a direction parameter to `compareRow`.
- `compareLine` and its helpers (`compareSortableValue`, `compareRow`) live in `src/utils/line-compare.ts`, imported by both `src/run/access-index.ts` and `src/tui/utils/table.ts`. Do not create a `run/ → tui/` import.
- Keep keyboard shortcuts documented in README and README_ES when behavior changes.

TUI filters are powerful and should stay documented:

- plain text search
- implicit `AND`
- `AND`, `OR`, `|`, parentheses
- negation with `!` or `NOT`
- field operators `:`, `=`, `!=`, `>`, `>=`, `<`, `<=`
- status families such as `status:2xx` and `status:5xx`
- wildcard `*`
- quoted values
- URL-decoded comparison
- query parameter filters such as `param:q`, `param:q=*select*`, `param:*=*sleep*`
- aliases such as `url`, `ua`, `st`, `ln`, `src`, `qs`, `mth`

## Reports

Supported report formats:

- Terminal (`--no-interactive` or non-TTY)
- JSON (`--json`)
- Markdown (`--markdown`)
- Self-contained offline HTML (`--html`)

HTML requirements:

- Self-contained CSS and JS.
- No external network resources.
- Escaped data only.
- Client-side filters and sortable tables.
- Executive summary, timeline, incidents, paths, IPs, UAs, payloads/actions where available.
- Print/PDF friendly.

## Security And Privacy

- Redact secrets in URLs and headers:
  - `token`, `_token`, `sid`, `session`, `password`, `passwd`, `key`, `secret`,
    `jwt`, `auth`, `authorization`.
- Escape all report output.
- Never execute log content.
- Avoid shelling out for archive parsing unless there is no safe JS alternative.
- Treat logs as sensitive customer data.
- Do not add telemetry. If ever added, it must be strict opt-in.
- Do not commit generated `citrx-*.json`, local run artifacts, or customer-specific paths.

## Testing

Use Vitest.

Core coverage areas:

- Parser: IPv4, IPv6, Apache/Nginx common/combined, invalid lines.
- Input: files, folders, stdin, `.gz`, `.br`, `.zip`, `.tar.gz`, `.tgz`.
- Rules: payload outcomes, recon, saturation, POST hotspots, fake bots, AI crawlers.
- Access index: pagination, filtering, sorting, random row reads.
- TUI hooks: summary/incident input, filters, exports, top values.
- CLI: flags, stdout/stderr, exit codes.
- HTML/Markdown/terminal reports.

Example logs in `examples/` are integration fixtures.

## Open Source Quality

Before final delivery:

- Run typecheck.
- Run tests relevant to the change; run full tests for broad behavior changes.
- Run lint if configured.
- Treat every commit as public open source history.
- Keep commits small, reviewable, and free of secrets, local-only paths,
  generated noise, and unrelated files.
- Do not commit `AGENTS.md` unless the user explicitly asks.
- Keep README and README_ES updated when CLI/TUI behavior changes.
- Keep README commands copy-pasteable.
- Prefer small, focused files.
- Add comments only for non-obvious logic.
- Do not add unrelated refactors.

## Package Rules

`package.json` must include:

- `name: "citrx"`.
- `bin: { "citrx": "./dist/cli.js" }`.
- `files` allowlist for publish.
- `engines.node` with supported LTS range.
- `license`.
- `repository`, `bugs`, and `homepage` when available.

Use semantic versioning.
