/**
 * File system helpers with deliberate, security-aware behaviour.
 *
 * Ledger files are opened with `O_APPEND | O_CREAT` (plus `O_NOFOLLOW` where the
 * platform supports it), created with mode `0o600`, and never silently follow a
 * symbolic link.
 *
 * Appends use a small synchronous `write` on a long-lived descriptor. For a single
 * audit line that is an order of magnitude faster than opening and closing a handle
 * per record, it guarantees the line reaches the OS before `record()` resolves, and
 * it avoids `FileHandle` finalization hazards in short-lived scripts.
 */

import * as fs from 'node:fs';
import { promises as fsp } from 'node:fs';

/** Permissions used when a ledger or checkpoint file is created on POSIX. */
export const FILE_MODE = 0o600;

const O_NOFOLLOW = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;

/** Turn a low-level Node filesystem error into an actionable message. */
export function describeFsError(error: unknown, filePath: string): Error {
  const err = error as NodeJS.ErrnoException;
  switch (err?.code) {
    case 'ENOENT':
      return new Error(`Cannot access "${filePath}": the file or its parent directory does not exist (ENOENT)`);
    case 'EACCES':
    case 'EPERM':
      return new Error(`Cannot access "${filePath}": permission denied (${err.code})`);
    case 'EISDIR':
      return new Error(`Cannot access "${filePath}": the path is a directory, expected a file (EISDIR)`);
    case 'ELOOP':
      return new Error(`Refusing to access "${filePath}": symbolic link (ELOOP)`);
    case 'ENOSPC':
      return new Error(`Cannot write "${filePath}": no space left on device (ENOSPC)`);
    default:
      return new Error(`Cannot access "${filePath}": ${err?.message ?? String(error)}`);
  }
}

/** Read a UTF-8 file synchronously, throwing a decorated error on failure. */
export function readTextSync(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    throw describeFsError(error, filePath);
  }
}

/** Read a UTF-8 file asynchronously, throwing a decorated error on failure. */
export async function readText(filePath: string): Promise<string> {
  try {
    return await fsp.readFile(filePath, 'utf8');
  } catch (error) {
    throw describeFsError(error, filePath);
  }
}

/** Refuse symbolic links and non-regular files, but allow a missing file. */
export function assertWritableTarget(filePath: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw describeFsError(error, filePath);
  }
  if (stat.isSymbolicLink()) {
    throw new Error(`Refusing to use "${filePath}": symbolic links are not allowed for ledger files`);
  }
  if (!stat.isFile()) {
    throw new Error(`Refusing to use "${filePath}": not a regular file`);
  }
}

/**
 * Open a ledger for appending, creating it with mode 0o600 when missing.
 * The symlink check runs before the open and `O_NOFOLLOW` closes the race on POSIX.
 */
export function openForAppend(filePath: string): number {
  assertWritableTarget(filePath);
  const flags = fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_WRONLY | O_NOFOLLOW;
  try {
    return fs.openSync(filePath, flags, FILE_MODE);
  } catch (error) {
    throw describeFsError(error, filePath);
  }
}

/**
 * Append one UTF-8 payload to an `O_APPEND` descriptor, retrying short writes.
 * Throws a decorated error when the write fails.
 */
export function appendToFd(fd: number, payload: string, filePath: string): void {
  const buffer = Buffer.from(payload, 'utf8');
  let offset = 0;
  while (offset < buffer.length) {
    const written = fs.writeSync(fd, buffer, offset, buffer.length - offset, null);
    if (written <= 0) {
      throw new Error(`Cannot write "${filePath}": the operating system accepted 0 bytes (ENOSPC or a closed descriptor)`);
    }
    offset += written;
  }
}

/** Close a descriptor, ignoring errors from descriptors that are already closed. */
export function closeFd(fd: number): void {
  try {
    fs.closeSync(fd);
  } catch {
    // Already closed or invalid: nothing left to release.
  }
}

/** Create (or truncate) a file with restrictive permissions and write UTF-8 text. */
export async function writeTextSecure(filePath: string, data: string): Promise<void> {
  try {
    await fsp.writeFile(filePath, data, { encoding: 'utf8', mode: FILE_MODE });
  } catch (error) {
    throw describeFsError(error, filePath);
  }
}
