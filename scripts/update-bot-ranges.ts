import { writeFile } from "node:fs/promises";

const SOURCES = [
  {
    // Google's common-crawlers list (Googlebot and other Google crawlers).
    // The old googlebot-only endpoint was retired; Google now directs callers here.
    url: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    out: "src/rules/data/googlebot-ranges.ts",
    constName: "GOOGLEBOT_RANGES"
  },
  {
    url: "https://www.bing.com/toolbox/bingbot.json",
    out: "src/rules/data/bingbot-ranges.ts",
    constName: "BINGBOT_RANGES"
  }
] as const;

for (const source of SOURCES) {
  const response = await fetch(source.url);

  if (!response.ok) {
    throw new Error(`Failed to fetch ${source.url}: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as {
    prefixes?: Array<{
      ipv4Prefix?: string;
      ipv6Prefix?: string;
    }>;
  };

  if (!Array.isArray(data.prefixes)) {
    throw new Error(
      `Unexpected payload from ${source.url}: missing "prefixes" array. ` +
        `Refusing to overwrite ${source.out}.`
    );
  }

  const ipv4: string[] = [];
  const ipv6: string[] = [];

  for (const entry of data.prefixes) {
    if (entry.ipv4Prefix) {
      ipv4.push(entry.ipv4Prefix);
    }
    if (entry.ipv6Prefix) {
      ipv6.push(entry.ipv6Prefix);
    }
  }

  if (ipv4.length === 0 && ipv6.length === 0) {
    throw new Error(
      `Fetched 0 ranges from ${source.url}. ` +
        `Refusing to overwrite ${source.out} with an empty snapshot.`
    );
  }

  const header =
    `// Snapshot from ${source.url}\n` +
    `// Updated: ${new Date().toISOString().slice(0, 10)}\n` +
    `// Re-run scripts/update-bot-ranges.ts to refresh.\n`;
  const body =
    `export const ${source.constName} = {\n` +
    `  ipv4: ${JSON.stringify(ipv4, null, 2)},\n` +
    `  ipv6: ${JSON.stringify(ipv6, null, 2)}\n` +
    `} as const;\n`;

  await writeFile(source.out, header + body);
  console.log(`Wrote ${source.out} (${ipv4.length} IPv4, ${ipv6.length} IPv6).`);
}
