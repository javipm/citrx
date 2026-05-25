# citrx

`citrx` is an open source CLI for local-first Apache/Nginx access log analysis.

It is being built in small verified phases. The current CLI supports local
access-log parsing, sessions, stdin, date filters, and deterministic security
incident detection and an interactive terminal console for plain text and
compressed files.

## Goals

- Detect abusive crawling, attack probes, suspicious POST traffic, fake bots,
  high-cost URLs, and malformed requests.
- Run useful local analysis before any optional AI step.
- Keep OpenAI analysis explicit, redacted, and post-analysis.
- Open an interactive terminal UI by default, with report exports available
  when needed.

## Requirements

- Node.js 24.15 or newer.
- pnpm 11 or newer.

## Development

```bash
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

Run the CLI from source:

```bash
pnpm run dev -- --help
pnpm run dev -- examples/access_ssl_log
pnpm run dev -- examples/access_ssl_log --json
```

After building:

```bash
node dist/cli.js --help
node dist/cli.js --version
node dist/cli.js /path/to/access.log
node dist/cli.js /path/to/access.log --no-interactive
node dist/cli.js /path/to/access.log --json
node dist/cli.js /path/to/access.log --incident-lines 1000
node dist/cli.js /path/to/access.log --markdown --out report.md
node dist/cli.js /path/to/access.log --html --out report.html
node dist/cli.js /path/to/access.log.gz --json
node dist/cli.js /path/to/archive.zip --json
cat /path/to/access.log | node dist/cli.js - --json
cat /path/to/access.log | node dist/cli.js --json
node dist/cli.js /path/to/access.log --format apache_combined
node dist/cli.js /path/to/access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z
node dist/cli.js /path/to/access.log --format custom:my_format --format-config ./formats.json
node dist/cli.js session list
node dist/cli.js session show <session-id>
```

Running `citrx` without paths in an interactive terminal fails fast with a
usage hint. Piped stdin still works without prompts.

## Phase 1.1

`citrx` currently supports plain text Apache/Nginx-style access logs.
It validates that inputs look like access logs before full analysis, then
streams files line by line to keep memory bounded for large logs.

Current report data:

- total, parsed, and invalid line counts
- filtered line counts when `--since`/`--until` are used
- total bytes served
- detected access-log format per input
- top IPs
- top paths
- top methods
- top statuses
- local security incidents
- stored access-log lines per incident

Built-in formats:

- `apache_common`
- `apache_combined`
- `nginx_combined`

By default, `--format auto` samples each input and selects the best parser. If
your logs use a custom format, pass `--format custom:<name>` and
`--format-config <path>`.

Custom format configs are JSON:

```json
{
  "formats": [
    {
      "name": "pipe",
      "pattern": "^(?<ip>\\S+)\\|(?<timestamp>[^|]+)\\|(?<method>\\S+)\\|(?<target>\\S+)\\|(?<protocol>HTTP/[^|]+)\\|(?<status>\\d{3})\\|(?<bytes>\\S+)$",
      "fields": {
        "ip": "ip",
        "timestamp": "timestamp",
        "method": "method",
        "target": "target",
        "protocol": "protocol",
        "status": "status",
        "bytes": "bytes"
      }
    }
  ]
}
```

## Terminal UI

By default, `citrx <paths...>` analyzes locally, stores a session, and opens an
interactive terminal console.

- Summary screen: global metrics, top IPs/paths/statuses, watchlist, and
  prioritized incidents.
- Incident screen: detailed evidence and a table of related access-log lines.
- Navigation: `Enter` opens an incident, `b` goes back, `/` filters, `s` changes
  sort column, `Tab` flips sort direction, `Space` selects a row, `A` selects
  visible rows, `a` asks OpenAI, `e` exports the current context, and `q` quits.

Incident filters support text search plus a small query syntax. Terms are joined
with `AND` by default, `OR`/`|` and parentheses are supported, and `!` negates a
term. Use `*` as the wildcard.

```text
method:POST status:200 url:*admin*
(method:POST OR method:PUT) status:2xx
(status:403 | status:404) !ua:*Googlebot*
ip:66.249.* bytes>50000
param:q
param:q=*select*
url:"/admin/login?q=camper"
```

Supported fields include `ip`, `method`, `status`, `path`, `url`/`target`, `ua`,
`bytes`, `param`, `source`, `line`, `time`, and `raw`.

OpenAI follow-up is scoped to the current screen. From the summary it receives a
compact global analysis. From an incident it receives only selected rows, or the
currently visible filtered rows when nothing is selected.

## Compressed Logs

`citrx` streams compressed inputs where possible and does not inflate them into
memory first. Supported inputs:

- `.gz`
- `.br`
- `.zip`
- `.tar.gz`
- `.tgz`

ZIP and TAR archives are scanned for candidate log entries such as `access.log`,
plain extensionless logs, `.log`, `.txt`, `.gz`, and `.br` files.

## Reports

Supported report outputs:

- terminal output with colors by default
- `--json`
- `--markdown`
- `--html`

Use `--out <path>` to write a report to disk. HTML reports are self-contained
and do not load external assets. Use `--no-color` or `NO_COLOR=1` to disable
terminal colors.

## Local Detection

`citrx` always runs local deterministic checks first. Current detections include:

- SQL injection payloads
- XSS payloads
- LFI/RFI and path traversal probes
- SSRF indicators
- command injection indicators
- sensitive file probes such as `.env`, `.git`, backups, and dumps
- uncommon HTTP methods
- aggregate high-volume path crawling
- query explosion on a single path
- POST hotspots

Sensitive query values such as tokens, passwords, session ids, auth keys, and
secrets are redacted from incident samples.

## Sessions

Every analysis creates a lightweight session by default. Sessions store the
redacted report model, source paths, timestamps, and summary data. They do not
copy raw log files.

```bash
citrx /path/to/access.log
citrx session list
citrx session show <session-id>
citrx session open <session-id>
citrx session export <session-id> --json --out report.json
citrx session delete <session-id>
```

Use `--no-session` for one-off runs. Set `CITRX_SESSION_DIR` to override the
session storage directory.

Use `--incident-lines <n>` to control how many parsed access-log lines are stored
per incident. The default is `500`; `0` stores counts only.

## Privacy

`citrx` is local-first. OpenAI is only called from the interactive explorer when
you explicitly ask a question, and only the selected incident plus limited,
redacted matching lines are sent.

## License

MIT
