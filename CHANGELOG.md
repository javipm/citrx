# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-07-07

### Fixed

- Clean `dist/` before each build so stale compiled artifacts (including the
  removed OpenAI integration) are no longer bundled into the published package.

## [0.5.0] - 2026-07-07

### Added

- CI workflow (typecheck, lint, test on push/PR).
- CHANGELOG.md.
- Detection coverage: null-byte stripping during payload normalization;
  additional SQLi signatures (context-anchored `--`/`#` comments,
  `UNION(SELECT`, exfiltration functions); XSS DOM sinks (`eval`, `innerHTML`,
  `insertAdjacentHTML`) and more event handlers; LFI variants (Windows
  backslash traversal, `php://input`/`phar://`, `/etc/shadow`, `/etc/sudoers`,
  `/proc/self/cmdline`); broadened recon paths (`.env` variants, `.git/HEAD`,
  `.svn`/`.hg`/`.bzr`, more backup extensions, `.ssh/id_rsa`, `.kube/config`,
  `wp-config.php`, `docker-compose.yml`, `.DS_Store`); more scanner
  user-agents (Burp Suite, OWASP ZAP, AppScan, hakrawler, ParamSpider,
  Aquatone, Metasploit) and the Grok AI crawler.

### Changed

- Redaction placeholder unified to `[REDACTED]` (previously URL-encoded
  `%5BREDACTED%5D` in incident samples); sensitive key list consolidated and
  extended with `credential`.
- SSRF detection now requires an internal/metadata destination
  (loopback, RFC1918, link-local, `169.254.169.254`), eliminating false
  positives on legitimate OAuth/redirect flows.
- Top-value aggregation keeps the full user-agent string; display truncation
  now happens only at render time.
- Upgraded dependencies: `commander` to v15 (requires Node `>=22.12`,
  `engines.node` updated accordingly), `typescript` to v6, `@types/node` to
  v26, `@types/yauzl` to v3, plus in-range minor/patch bumps for `ink`,
  `react`, `zod`, `yauzl`, `eslint`, `typescript-eslint`, `prettier`, `tsx`,
  and `vitest`.

### Fixed

- Quote-handling inconsistency in secret redaction.
- Redundant writer close.
- Command-injection newline-separator signature now matches the decoded
  request instead of a literal `%0a` that never survived normalization.
- Filtering by a top user-agent used the truncated label and never matched;
  it now filters on the full value.
- Filter matching no longer converts a literal `+` to a space when comparing
  free-text fields (e.g. `ua:`), fixing false negatives on user-agents such
  as `Googlebot/2.1 (+http://…)`.
- `update-bot-ranges` now points at Google's current `common-crawlers.json`
  endpoint (the old googlebot-only URL was retired) and refuses to overwrite a
  snapshot when the fetched payload is missing its `prefixes` array or yields
  zero ranges, instead of silently emptying the bot IP-range data. Refreshed
  the Googlebot/Bing IP-range snapshots.

### Performance

- Parse each request target URL once and reuse it for redaction and query
  signatures instead of parsing twice per line.
- Cache compiled wildcard regexes and the searchable-line string per filter
  instance in the TUI.

## [0.4.0] - 2026-06-10

### Changed

- Removed the OpenAI integration and related TUI answer flow.

### Fixed

- Avoided a top-level await in the publish script.
- Prompted before running publish preflight checks.

## [0.3.0] - 2026-06-02

### Added

- Release publish script.
- Top HTTP statuses view in the TUI.

### Changed

- Ranked saturation incidents by impact.

### Fixed

- Wrapped the publish script entrypoint.

### Docs

- Documented that citrx accepts files, folders, archives, and stdin.
- Swapped the satellite emoji for a lemon in README titles.
- Made CLAUDE.md a real file importing AGENTS.md.
- Published AGENTS.md/CLAUDE.md and synced shortcuts docs.

## [0.2.0] - 2026-06-01

### Changed

- Release build synced from the 0.1.x line; no functional changes beyond the
  version bump.

## [0.1.2] - 2026-05-28

### Changed

- Synced the CLI version from `package.json` at build time.

## [0.1.1] - 2026-05-28

Initial published release.

### Added

- Streaming Apache/Nginx access log parser with format auto-detection
  (`apache_common`, `apache_combined`, `nginx_combined`, custom formats).
- Deterministic detection rules for payload attacks (SQLi, XSS, LFI/RFI,
  SSRF, command injection), recon probes, HTTP anomalies, POST/auth abuse,
  fake bots, subnet/HEAD floods, and known actors.
- Incident scoring with correlation and persistence bonuses for global
  spikes and repeated route abuse.
- Interactive terminal UI (Ink) with summary and incident screens, structured
  filters, sort menu, top-values views, and export format menu.
- Inline AI answer panel in the TUI backed by OpenAI, triggered on demand.
- Temporary access-log index replacing in-memory sessions, powering incident
  row lookups and lazy-loaded pagination.
- Terminal, JSON, Markdown, and self-contained HTML reports.
- Init banner and startup UX polish.

### Changed

- Split `app.ts` into hooks, screens, and utils for the TUI.
- Split incidents by `kind` (`saturation`, `compromise`, `noise`) and
  reworked false-positive handling across rules.
- Reduced hot-path overhead in the streaming analysis pipeline.
- Cached access-log queries in the TUI for responsiveness on large logs.

### Fixed

- Kept large-log progress responsive during analysis.
- Tightened saturation guards and URL-saturation classification/promotion.
- Prevented partial incident exports and added export confirmation.
- Showed saturation incidents by default in the TUI summary.
- Clarified incident table status and detail layout.
- Added quit confirmation in the TUI.

### Docs

- Clarified TUI filters and 2xx-hit behavior.

[Unreleased]: https://github.com/javipm/citrx/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/javipm/citrx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/javipm/citrx/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/javipm/citrx/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/javipm/citrx/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/javipm/citrx/releases/tag/v0.1.1
