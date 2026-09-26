// /run/zetcert.lock, held by `sync` for its whole run. The certbot hooks never take it:
// certbot runs them while `sync` holds it.
import { closeSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import { UserError } from './errors';
import { LOCK_FILE, onDisk } from './paths';

export interface Lock {
  release(): void;
}

/** Whether `pid` is a running zetcert process (a reused PID of another program doesn't count). */
function isZetcert(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EPERM') return false;
  }
  try {
    return readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('zetcert');
  } catch {
    return true;
  }
}

export function acquireLock(): Lock {
  const file = onDisk(LOCK_FILE);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, 'wx', 0o644);
      writeSync(fd, `${process.pid}\n`);
      closeSync(fd);
      const release = () => {
        try {
          if (readFileSync(file, 'utf8').trim() === String(process.pid)) unlinkSync(file);
        } catch {
          // already gone
        }
        process.removeListener('exit', release);
      };
      process.on('exit', release);
      return { release };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    let pid = NaN;
    try {
      pid = Number.parseInt(readFileSync(file, 'utf8'), 10);
    } catch {
      // removed in the meantime
    }
    if (Number.isInteger(pid) && pid !== process.pid && isZetcert(pid)) {
      throw new UserError(`another zetcert sync is running (pid ${pid}); wait for it to finish`);
    }
    // A stale lock from a sync that didn't finish. Remove it only if it is still the same one.
    try {
      if (Number.parseInt(readFileSync(file, 'utf8'), 10) === pid || Number.isNaN(pid)) unlinkSync(file);
    } catch {
      // removed in the meantime
    }
  }
  throw new UserError(`can't take the lock ${LOCK_FILE}`);
}
