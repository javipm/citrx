# citrx

`citrx` is an open source CLI for local-first Apache/Nginx access log analysis.

It is being built in small verified phases. The current scaffold provides the
package, CLI entrypoint, tests, project metadata, and Phase 1 local access-log
analysis for plain text files.

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
cat /path/to/access.log | node dist/cli.js analyze - --json
cat /path/to/access.log | node dist/cli.js analyze --json
node dist/cli.js analyze /path/to/access.log --format apache_combined
node dist/cli.js analyze /path/to/access.log --since 2026-05-25T00:00:00Z --until 2026-05-25T23:59:59Z
node dist/cli.js analyze /path/to/access.log --format custom:my_format --format-config ./formats.json
node dist/cli.js session list
node dist/cli.js session show <session-id>
```

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

Compressed files, stdin, sessions, GeoIP, AI follow-up, Markdown, and HTML
reports are planned in later phases.

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
