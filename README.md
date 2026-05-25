# citrx

`citrx` is an open source CLI for local-first Apache/Nginx access log analysis.

It is being built in small verified phases. The current scaffold provides the
package, CLI entrypoint, tests, and project metadata. Log parsing starts in
Phase 1.

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
```

## Privacy

`citrx` is local-first. Future OpenAI integration will be opt-in and will send
only redacted aggregate findings by default, never full raw logs.

## License

MIT
