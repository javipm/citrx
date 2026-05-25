import { createReadStream } from "node:fs";
import { extname } from "node:path";
import { PassThrough, type Readable } from "node:stream";
import { createBrotliDecompress, createGunzip } from "node:zlib";

import * as tar from "tar-stream";
import * as yauzl from "yauzl";

export interface TextInputStream {
  label: string;
  stream: Readable;
}

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

function decompressByName(name: string, stream: Readable): Readable {
  if (name.endsWith(".gz")) {
    return stream.pipe(createGunzip());
  }

  if (name.endsWith(".br")) {
    return stream.pipe(createBrotliDecompress());
  }

  return stream;
}

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

function isZip(file: string): boolean {
  return file.toLowerCase().endsWith(".zip");
}

function isTarGz(file: string): boolean {
  const lower = file.toLowerCase();
  return lower.endsWith(".tar.gz") || lower.endsWith(".tgz");
}

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

class AsyncQueue<T> implements AsyncIterable<T> {
  private items: T[] = [];
  private resolvers: Array<(value: IteratorResult<T>) => void> = [];
  private ended = false;
  private error: unknown;

  push(item: T): void {
    const resolver = this.resolvers.shift();

    if (resolver) {
      resolver({ value: item, done: false });
      return;
    }

    this.items.push(item);
  }

  end = (): void => {
    this.ended = true;

    for (const resolver of this.resolvers.splice(0)) {
      resolver({ value: undefined, done: true });
    }
  };

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
