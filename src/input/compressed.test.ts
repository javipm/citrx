import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { brotliCompressSync, crc32, gzipSync } from "node:zlib";
import * as tar from "tar-stream";
import { describe, expect, it } from "vitest";

import { openTextInputStreams } from "./compressed.js";

async function streamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];

  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

async function readAllLines(file: string): Promise<string[]> {
  const lines: string[] = [];

  for await (const { stream } of openTextInputStreams(file)) {
    const text = (await streamToBuffer(stream)).toString("utf8");
    lines.push(text);
  }

  return lines;
}

/** Builds a minimal stored (uncompressed) ZIP archive containing a single entry. */
function createStoredZip(entryName: string, content: Buffer): Buffer {
  const name = Buffer.from(entryName);
  const checksum = crc32(content) >>> 0;
  const local = Buffer.alloc(30 + name.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(checksum, 14);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  name.copy(local, 30);

  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0, 14);
  central.writeUInt32LE(checksum, 16);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  name.copy(central, 46);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length + content.length, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([local, content, central, end]);
}

/** Builds an empty (no entries) stored ZIP archive. */
function createEmptyZip(): Buffer {
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(0, 8);
  end.writeUInt16LE(0, 10);
  end.writeUInt32LE(0, 12);
  end.writeUInt32LE(0, 16);
  end.writeUInt16LE(0, 20);
  return end;
}

describe("openTextInputStreams", () => {
  const content = Buffer.from(
    '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /compressed HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n'
  );

  async function withTempDir(fn: (directory: string) => Promise<void>): Promise<void> {
    const directory = await mkdtemp(join(tmpdir(), "citrx-compressed-test-"));

    try {
      await fn(directory);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  it("reads a plain (uncompressed) file as-is", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "access.log");
      await writeFile(file, content);

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("decompresses a .gz file", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "access.log.gz");
      await writeFile(file, gzipSync(content));

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("decompresses a .br (brotli) file", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "access.log.br");
      await writeFile(file, brotliCompressSync(content));

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("extracts a candidate entry from a .zip archive", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "access.zip");
      await writeFile(file, createStoredZip("access.log", content));

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("labels zip entries as archive::entryName", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "access.zip");
      await writeFile(file, createStoredZip("access.log", content));

      const labels: string[] = [];
      for await (const { label } of openTextInputStreams(file)) {
        labels.push(label);
      }

      expect(labels).toEqual([`${file}::access.log`]);
    });
  });

  it("extracts a candidate entry from a .tar.gz archive", async () => {
    await withTempDir(async (directory) => {
      const tarPack = tar.pack();
      tarPack.entry({ name: "access.log" }, content);
      tarPack.finalize();

      const file = join(directory, "access.tar.gz");
      await writeFile(file, gzipSync(await streamToBuffer(tarPack)));

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("extracts a candidate entry from a .tgz archive", async () => {
    await withTempDir(async (directory) => {
      const tarPack = tar.pack();
      tarPack.entry({ name: "access.log" }, content);
      tarPack.finalize();

      const file = join(directory, "access.tgz");
      await writeFile(file, gzipSync(await streamToBuffer(tarPack)));

      const lines = await readAllLines(file);
      expect(lines).toEqual([content.toString("utf8")]);
    });
  });

  it("preserves a final line without a trailing newline", async () => {
    await withTempDir(async (directory) => {
      const noTrailingNewline = Buffer.from(
        '203.0.113.10 - - [25/May/2026:03:12:49 +0200] "GET /no-newline HTTP/1.1" 200 42'
      );
      const file = join(directory, "access-no-newline.log.gz");
      await writeFile(file, gzipSync(noTrailingNewline));

      const lines = await readAllLines(file);
      expect(lines).toEqual([noTrailingNewline.toString("utf8")]);
      expect(lines[0]?.endsWith("\n")).toBe(false);
    });
  });

  it("throws when a .zip archive has no candidate access-log entries", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "empty.zip");
      await writeFile(file, createEmptyZip());

      await expect(readAllLines(file)).rejects.toThrow(
        /does not contain candidate access-log files/
      );
    });
  });

  it("throws when a .zip archive only contains non-candidate entries", async () => {
    await withTempDir(async (directory) => {
      const file = join(directory, "no-candidates.zip");
      await writeFile(
        file,
        createStoredZip("__MACOSX/._ignored", Buffer.from("irrelevant"))
      );

      await expect(readAllLines(file)).rejects.toThrow(
        /does not contain candidate access-log files/
      );
    });
  });

  it("throws when a .tar.gz archive has no candidate access-log entries", async () => {
    await withTempDir(async (directory) => {
      const tarPack = tar.pack();
      tarPack.entry({ name: ".hidden" }, Buffer.from("irrelevant"));
      tarPack.finalize();

      const file = join(directory, "no-candidates.tar.gz");
      await writeFile(file, gzipSync(await streamToBuffer(tarPack)));

      await expect(readAllLines(file)).rejects.toThrow(
        /does not contain candidate access-log files/
      );
    });
  });
});
