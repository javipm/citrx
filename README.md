# citrx

`citrx` is an open source CLI for local-first Apache/Nginx access log analysis.

It is being built in small verified phases. The current CLI supports local
access-log parsing, sessions, stdin, date filters, and deterministic security
incident detection for plain text and compressed files.

## Goals

- Detect abusive crawling, attack probes, suspicious POST traffic, fake bots,
  ASN concentration, high-cost URLs, and malformed requests.
- Run useful local analysis before any optional AI step.
- Keep OpenAI analysis explicit, redacted, and post-analysis.
- Produce terminal, JSON, Markdown, and self-contained HTML reports.

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
pnpm run dev -- analyze examples/access_ssl_log --json
```

After building:

```bash
node dist/cli.js --help
node dist/cli.js --version
node dist/cli.js analyze /path/to/access.log --json
node dist/cli.js analyze /path/to/access.log --markdown --out report.md
node dist/cli.js analyze /path/to/access.log --html --out report.html
node dist/cli.js analyze /path/to/access.log.gz --json
node dist/cli.js analyze /path/to/archive.zip --json
cat /path/to/access.log | node dist/cli.js analyze - --json
cat /path/to/access.log | node dist/cli.js analyze --json
node dist/cli.js analyze /path/to/access.log --format apache_combined
node dist/cli.js analyze /path/to/access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z
node dist/cli.js analyze /path/to/access.log --format custom:my_format --format-config ./formats.json
node dist/cli.js session list
node dist/cli.js session show <session-id>
```

Running `citrx analyze` with no paths, no flags, and an interactive terminal
starts a guided wizard for paths, output format, top-list size, and session
persistence. Piped stdin still works without prompts.

## Phase 1.1

`citrx analyze` currently supports plain text Apache/Nginx-style access logs.
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

AI follow-up is planned in a later phase.

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

## GeoIP / ASN

Pass `--geo` to enrich the top IPs with country, ASN, and organization data
after the local analysis finishes:

```bash
citrx analyze /path/to/access.log --geo
```

GeoIP uses the free `ipwho.is` API, runs sequential lookups to be gentle with
rate limits, and caches responses for seven days. Set `CITRX_CACHE_DIR` to
override the cache directory.

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
citrx analyze /path/to/access.log
citrx session list
citrx session show <session-id>
citrx session export <session-id> --json --out report.json
citrx session delete <session-id>
```

Use `--no-session` for one-off runs. Set `CITRX_SESSION_DIR` to override the
session storage directory.

## Privacy

`citrx` is local-first. Future OpenAI integration will be opt-in and will send
only redacted aggregate findings by default, never full raw logs.

## License

MIT
