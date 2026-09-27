// File access by the paths nginx, certbot and the config use (see paths.ts).
import {
  chmodSync,
  chownSync,
  closeSync,
  copyFileSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { hasTestRoot, onDisk } from './paths';

function isMissing(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

/**
 * Resolves the symlinks in `p` under a test root, where an absolute link target must stay inside
 * the temporary tree. On a real system the OS follows links itself, so `p` is returned as it is.
 * Every component is resolved; a missing one ends the resolution.
 */
export function resolveLinks(p: string): string {
  if (!hasTestRoot()) return p;
  let parts = path.resolve(p).split('/').filter(Boolean);
  let resolved = '/';
  for (let i = 0, hops = 0; i < parts.length; i++) {
    const next = path.join(resolved, parts[i] as string);
    let isLink: boolean;
    try {
      isLink = lstatSync(onDisk(next)).isSymbolicLink();
    } catch {
      return path.join(next, ...parts.slice(i + 1));
    }
    if (!isLink) {
      resolved = next;
      continue;
    }
    if (++hops > 40) throw new Error(`too many levels of symbolic links: ${p}`);
    const target = readlinkSync(onDisk(next));
    const joined = path.isAbsolute(target) ? target : path.join(resolved, target);
    parts = [...joined.split('/').filter(Boolean), ...parts.slice(i + 1)];
    resolved = '/';
    i = -1;
  }
  return resolved;
}

/** Whether `p` exists as a directory entry, even as a dangling symlink. */
export function entryExists(p: string): boolean {
  try {
    lstatSync(onDisk(path.join(resolveLinks(path.dirname(p)), path.basename(p))));
    return true;
  } catch {
    return false;
  }
}

/** The file's content, or undefined when it doesn't exist. */
export function readText(p: string): string | undefined {
  try {
    return readFileSync(onDisk(resolveLinks(p)), 'utf8');
  } catch (err) {
    if (isMissing(err)) return undefined;
    throw err;
  }
}

export function exists(p: string): boolean {
  try {
    statSync(onDisk(resolveLinks(p)));
    return true;
  } catch (err) {
    if (isMissing(err)) return false;
    throw err;
  }
}

export function isDirectory(p: string): boolean {
  try {
    return statSync(onDisk(resolveLinks(p))).isDirectory();
  } catch (err) {
    if (isMissing(err)) return false;
    throw err;
  }
}

/** The names in a directory, sorted; empty when it doesn't exist. */
export function listDir(p: string): string[] {
  try {
    return readdirSync(onDisk(resolveLinks(p))).sort();
  } catch (err) {
    if (isMissing(err)) return [];
    throw err;
  }
}

export function ensureDir(p: string, mode: number): void {
  mkdirSync(onDisk(p), { recursive: true, mode });
}

/** Creates one directory with exactly `mode`, whatever the umask. Returns false when it existed. */
export function makeDir(p: string, mode: number): boolean {
  try {
    mkdirSync(onDisk(p));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  }
  chmodSync(onDisk(p), mode);
  return true;
}

/** Removes a directory if it is empty. */
export function removeEmptyDir(p: string): void {
  try {
    rmdirSync(onDisk(p));
  } catch {
    // not empty, or already gone
  }
}

/**
 * Writes a file through a temporary file and a rename, so a reader never sees half a file.
 * The mode is set exactly, whatever the umask.
 */
export function writeFileAtomic(p: string, content: string | Buffer, mode: number): void {
  const file = onDisk(p);
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.zetcert-${process.pid}.tmp`;
  const fd = openSync(tmp, 'w', mode);
  try {
    writeFileSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, mode);
  renameSync(tmp, file);
}

export function removeFile(p: string): void {
  rmSync(onDisk(p), { force: true });
}

/** Copies a file through a temporary file and a rename, with an exact mode, owned by the running user. */
export function copyFileAtomic(from: string, to: string, mode: number): void {
  const file = onDisk(to);
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.zetcert-${process.pid}.tmp`;
  copyFileSync(onDisk(resolveLinks(from)), tmp);
  // Node 26 (libuv 1.52) keeps the source's owner, so root's copy of a user's file stayed theirs.
  chownSync(tmp, process.geteuid?.() ?? 0, process.getegid?.() ?? 0);
  chmodSync(tmp, mode);
  renameSync(tmp, file);
}
