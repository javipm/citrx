# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-08-31

Findings from auditing citrx against independent blind analyses of seven real
access-log corpora: seven analysts examined the same logs with only shell tools
and no knowledge of citrx, and every divergence was investigated.

### Fixed

- **Heavy hitters were dropped by the bounded-memory counters.** Top-N counting,
  per-path stats and the shared per-path IP/query-variant budgets all admitted
  keys first-come-first-served, so anything that only started appearing late in
  a long log was invisible regardless of volume. On a 3.9M-line corpus the single
  busiest path — 38% of all traffic — was missing from the report entirely.
  Counters now retain heavy hitters (space-saving admission) and every path is
  guaranteed a minimum sample of the shared budgets.
- **Ratios computed from truncated counters rejected the largest events.** Query
  and repeat-pressure ratios divided a capped numerator by the full request
  count, collapsing toward zero exactly when a path was busy enough to fill its
  caps. A ratio at or above its minimum is now trusted on its own (truncation can
  only push it down); below it, a filled counter defers to a corroborating
  pressure signal instead of a number known to be wrong.
- Directory inputs no longer abort the whole run when they contain a file that
  is not an access log (`error_log`, `xferlog`, OS junk). Such inputs are skipped
  with a warning and reported in `skippedInputs`; the run fails only when no
  input is an access log.
- Loopback and private addresses are excluded from per-IP behavior rules: a
  proxy hop was being reported as a critical Googlebot impersonation.
- Attack payloads requested from verified Googlebot/Bingbot IPs are demoted to
  noise — they describe a poisoned indexed URL, not an attack from that IP.
- Server distress is measured as a share of a path's requests rather than an
  absolute error count, which any high-volume path crosses.
- Aggregate bot roll-ups no longer receive the persistence score bonus.

### Added

- `auth_abuse:` — credential stuffing and login brute force on authentication
  endpoints, distinguishing distributed from single-source attempts. Previously
  only a raw POST count was reported for these paths.
- `ddos_sustained_ip_flood:` — one IP sustaining a high per-minute rate against
  very few URLs, catching floods paced below the per-second burst threshold.
- `server_capacity_distress` — site-wide 503/504/507/508 responses, the clearest
  evidence load actually degraded the site, previously invisible when spread
  across many clients.
- `fake_bot_campaign:` — collapses a coordinated impersonation campaign into one
  incident instead of dozens of near-identical per-IP rows.
- `fake_ai_bot:` — AI-crawler user-agents sent from outside the ranges their
  operators publish (OpenAI GPTBot / OAI-SearchBot, Perplexity PerplexityBot).
  `ai_scraper_known:` now reports `ipVerifiable`, so a self-declared crawler is
  never presented as verified.
- Saturation and auth incidents name the source IPs and heaviest subnet
  (`topIps`, `topIpShare`, `topSubnet`), and error storms name the failing paths
  (`topErrorPaths`).
- Recon escalates when a high-value target (`phpinfo.php`, `.env`,
  `.git/config`, a database dump…) actually returns content, regardless of
  success ratio — withdrawn when the response weighs exactly what the site
  serves on ordinary paths.

### Changed

- AI crawlers reach SATURATION on sustained path fan-out, bot-induced 5xx, or a
  dominant share of total traffic. Requiring path fan-out vetoed the worst real
  cases: a crawler hammering one faceted URL never accrues it, yet accounted for
  91% of one site's traffic while being reported as low-severity noise.
- Counts for keys admitted after a counter filled are upper bounds rather than
  exact. Peak memory rises on very large corpora as a result.

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
