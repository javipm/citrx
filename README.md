# citrx

`citrx` is a local-first CLI/TUI for Apache and Nginx access log analysis.

It streams large access logs, validates that inputs look like access logs,
detects security and abuse incidents locally, opens an interactive terminal UI
by default, and can optionally ask OpenAI for deeper analysis of the current
view or selected rows.

> Spanish documentation: [README_ES.md](./README_ES.md)

## Why citrx

Access logs often hide expensive crawlers, scanner noise, fake bots, SQLi/XSS
payloads, POST abuse, and traffic spikes. `citrx` is designed for DevOps,
security engineers, and backend developers who need to quickly answer:

- What happened?
- Which paths, IPs, methods, user-agents, and query params are involved?
- Which requests should I inspect?
- Which WAF/rate-limit rule could reduce the impact?

The default workflow is:

1. Run deterministic local analysis.
2. Explore incidents and raw matching requests in the TUI.
3. Filter, sort, inspect, and select rows.
4. Ask OpenAI only when you explicitly want help interpreting that context.

## Requirements

- Node.js `>=24.15`
- pnpm `>=11` for development

Published package usage is intended to work with `npx citrx` once released.

## Install And Run

Development checkout:

```bash
pnpm install
pnpm run dev -- /path/to/access.log
```

After build:

```bash
pnpm run build
node dist/cli.js /path/to/access.log
```

Common examples:

```bash
# Open the interactive TUI by default
citrx /var/log/nginx/access.log

# Analyze many paths, folders, and compressed files
citrx ./logs access.log.gz archive.zip

# Read from stdin
cat access.log | citrx -

# Non-interactive terminal report
citrx access.log --no-interactive

# JSON / Markdown / HTML reports
citrx access.log --json
citrx access.log --markdown --out report.md
citrx access.log --html --out report.html

# Date range
citrx access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z

# Explicit parser
citrx access.log --format apache_combined
```

`citrx analyze` was removed. Use:

```bash
citrx <paths...>
```

## CLI Options

```text
Usage: citrx [options] <paths...>

Options:
  --json                    Write machine-readable JSON output
  --markdown                Write Markdown output
  --html                    Write a self-contained HTML report
  --out <path>              Write report output to a file
  --no-interactive          Print terminal report instead of opening the TUI
  --format <format>         auto, apache_common, apache_combined,
                            nginx_combined, or custom:<name>
  --format-config <path>    JSON file with custom access-log formats
  --top <n>                 Limit top lists
  --since <date>            Include entries at or after this date
  --until <date>            Include entries at or before this date
  --include <glob>          Include paths matching this glob
  --exclude <glob>          Exclude paths matching this glob
  --no-color                Disable colored terminal output
  --debug                   Print debug details on failure
  -v, --version             Display version
```

`NO_COLOR=1` disables color. `CITRX_QUIET=1` disables startup UI/progress noise
for terminal output.

## Inputs

Supported inputs:

- individual access log files
- folders
- stdin with `-`
- `.gz`
- `.br`
- `.zip`
- `.tar.gz`
- `.tgz`

ZIP and TAR archives are scanned for candidate log files such as `access.log`,
`.log`, `.txt`, extensionless logs, `.gz`, and `.br` files.

`citrx` streams inputs and does not read full logs into memory. For the TUI it
creates a temporary access-log index under the OS temp directory. That workspace
is removed when the process exits.

## Access Log Formats

Built-in formats:

- `apache_common`
- `apache_combined`
- `nginx_combined`

Default mode is `--format auto`. `citrx` samples each input, chooses the best
parser, and fails early if the sample does not look like an Apache/Nginx-style
access log.

Custom formats are supported with `--format custom:<name>` and
`--format-config <path>`:

```json
{
  "formats": [
    {
      "name": "pipe",
      "pattern": "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<bytes>\\S+)\\|(?<userAgent>.*)$",
      "fields": {
        "ip": "ip",
        "timestamp": "timestamp",
        "method": "method",
        "target": "target",
        "protocol": "protocol",
        "status": "status",
        "bytes": "bytes",
        "userAgent": "userAgent"
      }
    }
  ]
}
```

## Interactive TUI

When stdout/stdin are TTYs and no report format is requested, `citrx` opens a
full-screen terminal UI.

### Summary Screen

Shows:

- analysis summary
- navigable incident panels (three tabs)
- complete indexed access-log table

The incident area has three tabs navigable with `Tab`:

| Tab                      | Contents                                                                  |
| ------------------------ | ------------------------------------------------------------------------- |
| **SATURATION** (default) | Rate bursts, DDoS, AI crawlers, abusive bots — traffic/resource abuse     |
| **SECURITY**             | SQLi/XSS/LFI payloads, recon, fake bots, scanner UA — compromise attempts |
| **OTHER**                | Low-signal or noise incidents filtered from the main panels               |

`Tab` cycles: access log → SATURATION → SECURITY → OTHER → access log.

Incidents marked `2XX_HIT` had at least one `2xx` response, meaning the
payload or probe received a successful HTTP reply.

Keys:

```text
Tab              switch focus between access log and incident panels
↑/↓              move row
PgUp/PgDn        page through rows
Enter / d        open incident or request detail
f or /           filter access-log rows
s or S           open sort menu
t                open global top values
Space            select current row
A                select visible rows
a                ask OpenAI about current view/selection
e                open export menu (CSV, JSON, TSV)
q                ask before quit
h                contextual help overlay (keys + filter syntax)
```

### Incident Screen

Shows incident evidence and all related access-log lines.

Keys are intentionally similar to the summary screen:

```text
↑/↓              move row
PgUp/PgDn        page through rows
Enter / d        open request detail
t                open top values for this incident
Space            select current row
A                select visible rows
f or /           filter rows
s or S           open sort menu
a                ask OpenAI about this incident/selection
e                open export menu (CSV, JSON, TSV)
b                back to summary
q                ask before quit
h                contextual help overlay
```

Incident export is shown only after all related rows have finished loading, so
exports do not accidentally contain a partial background-hydrated sample.

### Export Menu

Press `e` from the summary or incident screen to choose an export format before
writing the current context. Summary exports write the selected rows, or the
full filtered access-log result when nothing is selected. Incident exports write
the selected incident rows, or all currently filtered incident rows.

```text
↑/↓              choose CSV, JSON, or TSV
c / j / t        export directly as CSV, JSON, or TSV
Enter            export using selected format
Esc / Backspace  cancel
```

### Sort Menu

Press `s` or `S` from the summary or incident screen to open a centered sort
menu over the log. The menu lets you choose the sort field and direction before
any expensive re-indexing happens.

```text
←/→              switch between field and direction columns
↑/↓              choose field or direction
Space            select current column and move to the next step
Enter            apply sort and close the menu
Esc / Backspace  cancel
```

Selected values are highlighted in the menu. When a large filtered/sorted view
or top-value set is being computed, or an export is running, the TUI shows a
loading status instead of appearing frozen.

### Top Values Screen

Available from summary or incident screens with `t`.

Panels:

- top IPs
- top paths
- top user-agents
- top query params
- top query param values

Keys:

```text
Tab              switch panel
↑/↓              move inside panel
Enter            apply a filter using selected value
a                ask OpenAI about the visible top values
t / b / Esc      back
q                ask before quit
h                contextual help overlay
```

If a filter is active, top values are computed from the filtered subset.

### Request Detail

Open with `Enter` or `d` on a log row. It shows full source, timestamp, IP,
method, status, bytes, path, target, user-agent, and raw line with wrapping.

```text
↑/↓ PgUp/PgDn    scroll
d / b / Esc      close
q                ask before quit
h                contextual help overlay
```

## Filtering

Filters work on the global access log and incident-related rows.

You can use filters from the summary access-log table, incident rows, and top
values drill-downs. They are case-insensitive and work as a small query language:

- plain text searches across IP, time, method, path, target, status, bytes, UA,
  and raw line
- adjacent terms mean `AND`
- explicit `AND`, `OR`, `|`, parentheses, and negation with `!` or `NOT`
- `:` means contains for normal fields, while `=` means exact match
- `!=` negates a field match
- `>`, `>=`, `<`, `<=` work for `status`, `bytes`, and `line`
- `status:2xx`, `status:3xx`, `status:4xx`, and `status:5xx` match status families
- `*` wildcards are anchored, so `ip:66.249.*` matches that prefix
- quoted values allow spaces or symbols: `ua:"Googlebot/2.1"`
- URL-encoded filter values are decoded before matching

Common examples:

```text
method:POST status:200 url:*admin*
(method:POST OR method:PUT) status:2xx
(status:403 | status:404) !ua:*Googlebot*
ip:66.249.* bytes>50000
status:5xx path:/checkout
method!=GET status>=400
param:q
param:q=*select*
param:*=*sleep*
query:*utm_*
url:"/admin/login?q=camper"
raw:"union select"
source:access.log line>=10000 line<20000
```

Fields:

```text
ip, method, status, path, target, url, ua, bytes, param, query, source, line, time, raw
```

Useful aliases:

```text
url -> target
timestamp -> time
userAgent -> ua
st -> status
ln -> line
src -> source
qs -> query
mth -> method
params -> param
```

Parameter filters have two modes:

```text
param:q              any request with a q parameter
param:q=*select*     q parameter whose value contains "select"
param:*=*token*      any parameter value containing "token"
```

Bare text is convenient for quick hunting:

```text
googlebot checkout
198.51.100.10 wp-admin
```

Those are equivalent to requiring both words somewhere in the searchable line.

## OpenAI Mode

OpenAI is never called during the initial analysis. It is only called when you
press `a` in the TUI.

Setup:

```bash
export OPENAI_API_KEY="sk-proj-..."
```

Optional:

```bash
export CITRX_OPENAI_MODEL="gpt-5.4-mini"
export CITRX_AI_MAX_LINES="200"
export CITRX_AI_MAX_CHARS="60000"
```

OpenAI receives compact, redacted context:

- report summary
- time stats
- top IPs/paths/methods/statuses
- top behavior stats
- selected incident evidence
- selected rows, or visible filtered rows when nothing is selected
- user-agent references instead of repeating long UAs

The answer is shown in a dedicated scrollable TUI screen with lightweight
Markdown rendering.

Important: access logs do not contain ASN data. If ASN/organization is not
present in the local context, the model is instructed not to invent it.

## Reports

Supported outputs:

- colored terminal report
- JSON (`--json`)
- Markdown (`--markdown`)
- self-contained offline HTML (`--html`)

Use `--out <path>` to write Markdown/HTML/JSON to disk.

HTML reports:

- self-contained CSS/JS
- no external network resources
- escaped output
- sortable/filterable tables
- print/PDF friendly

## Incident Types

Every incident has a `kind` field that drives which TUI panel it appears in:

| Kind         | Panel      | Examples                                                      |
| ------------ | ---------- | ------------------------------------------------------------- |
| `compromise` | SECURITY   | SQLi/XSS/LFI payloads, recon probes, fake bots, scanner tools |
| `saturation` | SATURATION | DDoS bursts, AI crawlers, abusive crawlers, POST hotspots     |
| `noise`      | OTHER      | Low-signal patterns unlikely to need immediate action         |

`citrx` currently emits these incident families.

### Payload And Recon Rules

| ID prefix               | Category            | Kind       | Meaning                                                                               |
| ----------------------- | ------------------- | ---------- | ------------------------------------------------------------------------------------- |
| `sqli:`                 | `sql_injection`     | compromise | SQL injection payload indicators such as `union select`, sleep/benchmark, encoded SQL |
| `xss:`                  | `xss`               | compromise | script/browser execution indicators                                                   |
| `lfi_rfi:`              | `path_traversal`    | compromise | traversal, local/remote file inclusion, `php://filter`, sensitive paths               |
| `ssrf:`                 | `ssrf`              | compromise | localhost, metadata IPs/hosts, callback-like URL params                               |
| `command_injection:`    | `command_injection` | compromise | shell metacharacters plus command indicators                                          |
| `recon_sensitive_file:` | `recon`             | compromise | probes for `.env`, `.git`, backups, dumps, internals                                  |
| `rare_method:`          | `http_anomaly`      | noise      | uncommon HTTP methods (`CONNECT`, `TRACE`, `OPTIONS`)                                 |

Payload incidents are grouped **by attacker IP**, not by path, so one incident
per IP regardless of how many paths they probe. Scoring by response outcome:

- Any `2xx` response → `SECURITY`, `critical/100` + `2XX_HIT` flag (payload landed)
- Any `5xx` response → `SECURITY`, `critical/90`
- Only blocked/redirected responses → `OTHER` noise; useful context, not proven impact

`recon_sensitive_file` requires at least **2 successful responses** or a **10% success
ratio** to avoid flagging typical 404 scanners.

### Aggregate Path Rules

| ID prefix          | Category           | Kind             | Meaning                                                                        |
| ------------------ | ------------------ | ---------------- | ------------------------------------------------------------------------------ |
| `abusive_crawl:`   | `abusive_crawling` | saturation/noise | material served path pressure or distributed crawling on a non-entrypoint path |
| `query_explosion:` | `abusive_crawling` | noise            | one path requested with many query variants                                    |
| `post_hotspot:`    | `post_hotspot`     | noise            | endpoint receives unusually many POST requests                                 |

### Rate And DDoS Rules

| ID prefix                   | Category | Kind       | Meaning                                                                               |
| --------------------------- | -------- | ---------- | ------------------------------------------------------------------------------------- |
| `ddos_rps_burst_single_ip:` | `ddos`   | saturation | one IP exceeds per-second RPS threshold for consecutive seconds                       |
| `ddos_global_rps_spike`     | `ddos`   | saturation | global RPS exceeds baseline for consecutive seconds                                   |
| `http_head_flood:`          | `ddos`   | saturation | one IP sends a high ratio and high peak of HEAD requests                              |
| `ddos_distributed_subnet:`  | `ddos`   | saturation | IPv4 `/24` or IPv6 `/48` exceeds RPS and unique-IP thresholds for consecutive seconds |

### HTTP Error Storm Rules

| ID prefix         | Category       | Kind       | Meaning                                                        |
| ----------------- | -------------- | ---------- | -------------------------------------------------------------- |
| `http_4xx_storm:` | `http_anomaly` | noise      | one IP generates many 4xx responses in adjacent minute buckets |
| `http_5xx_storm:` | `http_anomaly` | saturation | one IP generates many 5xx responses in adjacent minute buckets |

### Bot And Scanner Rules

| ID prefix                   | Category           | Kind             | Meaning                                                                |
| --------------------------- | ------------------ | ---------------- | ---------------------------------------------------------------------- |
| `ai_scraper_known:`         | `ai_scraper`       | saturation/noise | known AI crawler or AI assistant user-agent, grouped by bot            |
| `scanner_ua_known:`         | `scanner`          | compromise       | known scanner/offensive tooling user-agent                             |
| `scanner_signature_paths:`  | `scanner`          | compromise       | one IP touches many known fingerprint paths in adjacent minute buckets |
| `single_ip_path_explosion:` | `abusive_crawling` | saturation       | one IP exceeds **10 unique paths/minute** sustained                    |
| `ua_rotation_same_ip:`      | `http_anomaly`     | noise            | one IP uses many different user-agents **and** peak RPS ≥ 5            |
| `fake_bot_googlebot:`       | `fake_bot`         | compromise       | UA claims core Googlebot but IP is outside published Googlebot ranges  |
| `fake_bot_bingbot:`         | `fake_bot`         | compromise       | UA claims bingbot but IP is outside published Bing ranges              |

Detection notes:

- `single_ip_path_explosion` requires **pathsPerMinute ≥ 10**, not just raw count.
  Normal page loads fetching many assets do not trigger it.
- `abusive_crawl` enters `SATURATION` only when enough requests are actually
  served (`2xx`/material `5xx`) and the path has a real served-per-minute peak.
  Redirect-heavy or 403-heavy traffic stays in `OTHER`.
- `ua_rotation_same_ip` requires **peak RPS ≥ 5**, but is still `OTHER` unless
  another detector finds payload impact. Shared NAT (e.g. AWS offices) naturally
  generates many user-agents at low rate without being malicious.
- `fake_bot_*` incidents require **at least 10 requests** from that IP.
- IPs confirmed as legitimate Googlebot or Bingbot (verified against published
  ranges) are excluded from all bot and scanner detections.
- `ai_scraper_known` is `SATURATION` only for bursty path fan-out; high total
  crawler volume spread over days stays in `OTHER`.

Googlebot and Bingbot range snapshots are stored in source. Refresh them with:

```bash
pnpm run update-bot-ranges
```

## Scoring

Each incident has:

- `kind`: `compromise`, `saturation`, or `noise` (drives TUI panel placement)
- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `score`: `0` to `100`
- `evidence`: typed key/value data for audit
- `samples`: redacted examples when relevant
- `successful?`: `true` when at least one matching response was `2xx`

Severity thresholds:

| Score range | Severity   |
| ----------- | ---------- |
| 0–24        | `info`     |
| 25–49       | `low`      |
| 50–74       | `medium`   |
| 75–89       | `high`     |
| 90–100      | `critical` |

Post-processing multipliers applied after base scoring:

- `+10` when the same `evidence.ip` appears in two or more incidents (correlated attacker)
- `+15` when a pattern persists for at least 30 minutes (persistence bonus)
- `-10` for moderate known AI crawlers that requested `robots.txt`

Notes:

- Persistence bonus does **not** apply to `ai_scraper_known:*` — AI crawlers naturally
  run for weeks, so duration alone is not a signal.
- Scores are sorted within each panel by `kind` weight first
  (compromise → saturation → noise), then by score descending.
- Scores are capped to `[0, 100]`, then severity is recalculated from the final score.

## Security And Privacy

- Local analysis first.
- No telemetry.
- OpenAI only on explicit `a` action.
- Secrets in URL/query values are redacted.
- HTML output is escaped.
- Log content is never executed.
- Runtime TUI index files are temporary and deleted on exit.

Redacted query keys include:

```text
token, _token, sid, session, password, passwd, key, secret, jwt, auth, authorization
```

## Development

```bash
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

Run from source:

```bash
pnpm run dev -- examples/access_ssl_log
pnpm run dev -- examples/access_ssl_log --json
```

Update bot IP range snapshots:

```bash
pnpm run update-bot-ranges
```

## Project Status

`citrx` is pre-1.0 and not published yet. CLI and report shapes may still
change while the core workflow is refined.

## License

MIT
