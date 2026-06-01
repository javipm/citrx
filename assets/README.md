# assets

Screenshots and media referenced by [`README.md`](../README.md) and
[`README_ES.md`](../README_ES.md). Images are WebP (smaller than PNG at the same
visual quality).

| File                   | Screen                                                       |
| ---------------------- | ------------------------------------------------------------ |
| `tui-summary.webp`     | Summary screen: incident tabs + global access-log table      |
| `tui-incident.webp`    | Incident screen: evidence + related rows                     |
| `tui-top-values.webp`  | Top values screen (IPs, paths, UAs, params)                  |
| `tui-filter.webp`      | Filter bar with a query language expression                  |
| `report-terminal.webp` | `--no-interactive` terminal report                           |
| `report-html.webp`     | Self-contained HTML report opened in a browser               |

Regenerate WebP from a PNG capture:

```bash
cwebp -q 82 capture.png -o assets/tui-summary.webp
```

Tips for clean captures:

- Run against a synthetic log (`examples/acme/access_log`), never real data.
- Dark terminal theme, monospaced font with good box-drawing glyphs.
- Window around 120×40 so tables are not truncated.
