import { createReadStream } from "node:fs";
import { extname } from "node:path";
import { PassThrough, type Readable } from "node:stream";
import { createBrotliDecompress, createGunzip } from "node:zlib";

import * as tar from "tar-stream";
import * as yauzl from "yauzl";

/**
 * A named readable text stream, typically representing one log file
 * extracted from a plain or compressed archive.
 */
export interface TextInputStream {
  /** Human-readable identifier for the stream, e.g. `"archive.zip::logs/access.log"`. */
  label: string;
  /** Readable byte stream of the (already decompressed) text content. */
  stream: Readable;
}

/**
 * Opens one or more decompressed text streams from a log file.
 *
 * - `.zip` → yields one {@link TextInputStream} per candidate entry inside the archive.
 * - `.tar.gz` / `.tgz` → yields one {@link TextInputStream} per candidate entry.
 * - `.gz` / `.br` → yields a single decompressed stream.
 * - Any other file → yields the raw stream as-is.
 *
 * @param file Absolute or relative path to the file to open.
 * @yields {@link TextInputStream} objects ready to be consumed line-by-line.
 * @throws If an archive contains no candidate access-log entries.
 */
export async function* openTextInputStreams(file: string): AsyncGenerator<TextInputStream> {
  if (isZip(file)) {
    yield* openZipTextInputStreams(file);
    return;
  }

  if (isTarGz(file)) {
    yield* openTarTextInputStreams(file);
    return;
  }

  yield {
    label: file,
    stream: decompressByName(file, createReadStream(file))
  };
}

/**
 * Wraps `stream` in a decompression transform based on the file extension of `name`.
 * Supports `.gz` (gunzip) and `.br` (brotli). All other extensions pass through unchanged.
 *
 * @param name Filename used to detect the compression format.
 * @param stream Raw compressed (or plain) readable stream.
 * @returns A readable stream that emits decompressed bytes.
 */
function decompressByName(name: string, stream: Readable): Readable {
  if (name.endsWith(".gz")) {
    return stream.pipe(createGunzip());
  }

  if (name.endsWith(".br")) {
    return stream.pipe(createBrotliDecompress());
  }

  return stream;
}

/**
 * Yields a {@link TextInputStream} for every candidate entry inside a ZIP archive.
 * Directory entries and non-candidate filenames (see {@link isCandidateArchiveEntry}) are skipped.
 *
 * @param file Path to the `.zip` file.
 * @yields One stream per qualifying archive entry, label formatted as `"file::entryName"`.
 * @throws If the archive contains no candidate entries.
 */
async function* openZipTextInputStreams(file: string): AsyncGenerator<TextInputStream> {
  const zip = await openZip(file);
  let yielded = 0;

  try {
    while (true) {
      const entry = await readZipEntry(zip);

      if (!entry) {
        break;
      }

      if (entry.fileName.endsWith("/") || !isCandidateArchiveEntry(entry.fileName)) {
        continue;
      }

      const stream = await openZipEntryStream(zip, entry);
      yielded += 1;

      yield {
        label: `${file}::${entry.fileName}`,
        stream: decompressByName(entry.fileName, stream)
      };
    }
  } finally {
    zip.close();
  }

  if (yielded === 0) {
    throw new Error(`Archive does not contain candidate access-log files: ${file}`);
  }
}

/**
 * Yields a {@link TextInputStream} for every candidate entry inside a `.tar.gz` / `.tgz` archive.
 * Non-file entries and non-candidate filenames (see {@link isCandidateArchiveEntry}) are skipped.
 * Uses an {@link AsyncQueue} to bridge the event-driven tar-stream API with async iteration.
 *
 * @param file Path to the `.tar.gz` or `.tgz` file.
 * @yields One stream per qualifying archive entry, label formatted as `"file::entryName"`.
 * @throws If the archive contains no candidate entries or a stream error occurs.
 */
async function* openTarTextInputStreams(file: string): AsyncGenerator<TextInputStream> {
  const extract = tar.extract();
  const queue = new AsyncQueue<TextInputStream>();
  let yielded = 0;

  extract.on("entry", (header, stream, next) => {
    if (header.type !== "file" || !isCandidateArchiveEntry(header.name)) {
      stream.resume();
      stream.on("end", next);
      stream.on("error", queue.fail);
      return;
    }

    const pass = new PassThrough();
    yielded += 1;
    stream.on("end", next);
    stream.on("error", (error) => {
      pass.destroy(error);
      queue.fail(error);
    });
    stream.pipe(pass);
    queue.push({
      label: `${file}::${header.name}`,
      stream: decompressByName(header.name, pass)
    });
  });

  extract.on("finish", () => queue.end());
  extract.on("error", queue.fail);
  createReadStream(file).pipe(createGunzip()).pipe(extract);

  for await (const item of queue) {
    yield item;
  }

  if (yielded === 0) {
    throw new Error(`Archive does not contain candidate access-log files: ${file}`);
  }
}

/**
 * Promisified wrapper around `yauzl.open`. Opens the ZIP file with `lazyEntries: true`
 * so entries are read on demand via {@link readZipEntry}.
 *
 * @param file Path to the `.zip` file.
 * @returns Resolved `yauzl.ZipFile` handle.
 */
function openZip(file: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true }, (error, zip) => {
      if (error) {
        reject(error);
        return;
      }

      if (!zip) {
        reject(new Error(`Could not open zip archive: ${file}`));
        return;
      }

      resolve(zip);
    });
  });
}

/**
 * Reads the next entry from an open ZIP file (lazy mode).
 *
 * @param zip An open `yauzl.ZipFile` in `lazyEntries` mode.
 * @returns The next `yauzl.Entry`, or `null` when all entries have been read.
 */
function readZipEntry(zip: yauzl.ZipFile): Promise<yauzl.Entry | null> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      zip.off("entry", onEntry);
      zip.off("end", onEnd);
      zip.off("error", onError);
    };
    const onEntry = (entry: yauzl.Entry) => {
      cleanup();
      resolve(entry);
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };

    zip.once("entry", onEntry);
    zip.once("end", onEnd);
    zip.once("error", onError);
    zip.readEntry();
  });
}

/**
 * Promisified wrapper around `yauzl.ZipFile.openReadStream`.
 *
 * @param zip The open ZIP file that owns `entry`.
 * @param entry The entry to open a read stream for.
 * @returns A readable stream of the raw (possibly compressed) entry bytes.
 */
function openZipEntryStream(zip: yauzl.ZipFile, entry: yauzl.Entry): Promise<Readable> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error) {
        reject(error);
        return;
      }

      if (!stream) {
        reject(new Error(`Could not read zip entry: ${entry.fileName}`));
        return;
      }

      resolve(stream);
    });
  });
}

/** Returns `true` if `file` has a `.zip` extension (case-insensitive). */
function isZip(file: string): boolean {
  return file.toLowerCase().endsWith(".zip");
}

/** Returns `true` if `file` has a `.tar.gz` or `.tgz` extension (case-insensitive). */
function isTarGz(file: string): boolean {
  const lower = file.toLowerCase();
  return lower.endsWith(".tar.gz") || lower.endsWith(".tgz");
}

/**
 * Determines whether an archive entry is a candidate access-log file.
 *
 * Excluded: `__MACOSX/` prefixed paths, dotfiles.
 * Included: entries with no extension, or extension `.log`, `.txt`, `.gz`, `.br`,
 * or any filename that contains the word `"access"`.
 *
 * @param name Entry filename as stored in the archive (forward- or back-slash separated).
 * @returns `true` if the entry should be opened and yielded.
 */
function isCandidateArchiveEntry(name: string): boolean {
  const normalized = name.replaceAll("\\", "/").toLowerCase();
  const base = normalized.split("/").pop() ?? normalized;

  if (normalized.startsWith("__macosx/") || base.startsWith(".")) {
    return false;
  }

  const extension = extname(base);
  return (
    extension === "" ||
    [".log", ".txt", ".gz", ".br"].includes(extension) ||
    base.includes("access")
  );
}

/**
 * A concurrency-safe async FIFO queue that bridges event-driven producers with
 * `for await…of` consumers.
 *
 * Producers call {@link push} to enqueue items, {@link end} to signal completion,
 * or {@link fail} to signal a fatal error. Consumers iterate with
 * `for await (const item of queue)`.
 *
 * @template T The type of items held in the queue.
 */
class AsyncQueue<T> implements AsyncIterable<T> {
  private items: T[] = [];
  private resolvers: Array<(value: IteratorResult<T>) => void> = [];
  private ended = false;
  private error: unknown;

  /**
   * Enqueues `item`. If a consumer is already waiting, it is resolved immediately;
   * otherwise the item is buffered.
   */
  push(item: T): void {
    const resolver = this.resolvers.shift();

    if (resolver) {
      resolver({ value: item, done: false });
      return;
    }

    this.items.push(item);
  }

  /** Signals that no more items will be pushed. Any waiting consumers are resolved with `done: true`. */
  end = (): void => {
    this.ended = true;

    for (const resolver of this.resolvers.splice(0)) {
      resolver({ value: undefined, done: true });
    }
  };

  /**
   * Records `error` and calls {@link end}. The async iterator will throw once
   * all buffered items have been consumed.
   */
  fail = (error: unknown): void => {
    this.error = error;
    this.end();
  };

  async *[Symbol.asyncIterator](): AsyncIterator<T> {
    while (true) {
      if (this.items.length > 0) {
        yield this.items.shift() as T;
        continue;
      }

      if (this.error) {
        throw this.error;
      }

      if (this.ended) {
        return;
      }

      const next = await new Promise<IteratorResult<T>>((resolve) => {
        this.resolvers.push(resolve);
      });

      if (next.done) {
        if (this.error) {
          throw this.error;
        }
        return;
      }

      yield next.value;
    }
  }
}
