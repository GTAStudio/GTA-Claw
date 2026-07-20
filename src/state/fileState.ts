import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

export class KeyedSerialQueue {
  private readonly tails = new Map<string, Promise<void>>();

  run<T>(key: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.tails.set(key, tail);
    void tail.then(() => {
      if (this.tails.get(key) === tail) {
        this.tails.delete(key);
      }
    });
    return result;
  }
}

export class CorruptStateError extends Error {
  readonly filePath: string;

  constructor(filePath: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CorruptStateError";
    this.filePath = filePath;
  }
}

export function scopedStatePath(
  rootDir: string,
  collection: string,
  scope: string,
): string {
  if (!scope.trim()) {
    throw new Error("Persistence scope must not be empty");
  }

  const digest = createHash("sha256").update(scope, "utf8").digest("hex");
  return join(resolve(rootDir), collection, `${digest}.json`);
}

export async function readJsonFile(
  filePath: string,
  maxBytes?: number,
): Promise<unknown | undefined> {
  if (maxBytes !== undefined) {
    try {
      const metadata = await stat(filePath);
      if (!metadata.isFile() || metadata.size > maxBytes) {
        throw new CorruptStateError(
          filePath,
          `State path is not a regular file within the ${maxBytes}-byte limit: ${filePath}`,
        );
      }
    } catch (err) {
      if (isNodeError(err) && err.code === "ENOENT") {
        return undefined;
      }
      throw err;
    }
  }

  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (err) {
    if (isNodeError(err) && err.code === "ENOENT") {
      return undefined;
    }
    throw new Error(`Failed to read state file: ${filePath}`, { cause: err });
  }

  try {
    return JSON.parse(raw) as unknown;
  } catch (err) {
    throw new CorruptStateError(
      filePath,
      `State file contains invalid JSON: ${filePath}`,
      { cause: err },
    );
  }
}

export async function atomicWriteJson(
  filePath: string,
  value: unknown,
): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });

  const tempPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  const serialized = `${JSON.stringify(value, null, 2)}\n`;

  try {
    await writeFile(tempPath, serialized, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(tempPath, filePath);
  } catch (err) {
    throw new Error(`Failed to atomically write state file: ${filePath}`, {
      cause: err,
    });
  } finally {
    await rm(tempPath, { force: true }).catch(() => undefined);
  }
}

export async function quarantineCorruptState(
  filePath: string,
): Promise<string> {
  const backupPath = `${filePath}.corrupt-${Date.now()}-${randomUUID()}`;
  try {
    await rename(filePath, backupPath);
    return backupPath;
  } catch (err) {
    throw new Error(`Failed to quarantine corrupt state file: ${filePath}`, {
      cause: err,
    });
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && "code" in err;
}
