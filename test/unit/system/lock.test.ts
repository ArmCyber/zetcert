import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { acquireLock } from '../../../src/system/lock';
import { tempRoot, zetcertLikeProcess } from '../helpers';

describe('lock', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => {
    root = tempRoot();
    root.write('/run/.keep', '');
  });
  afterEach(() => root.cleanup());

  it('takes and releases the lock', () => {
    const lock = acquireLock();
    expect(readFileSync(root.path('/run/zetcert.lock'), 'utf8')).toBe(`${process.pid}\n`);
    lock.release();
    expect(() => readFileSync(root.path('/run/zetcert.lock'))).toThrow();
    acquireLock().release();
  });

  it('takes over a stale lock', () => {
    root.write('/run/zetcert.lock', '999999999\n');
    acquireLock().release();
  });

  it('ignores a live process that is not zetcert', () => {
    // PID 1 is alive but isn't zetcert.
    root.write('/run/zetcert.lock', '1\n');
    acquireLock().release();
  });

  it('refuses while another zetcert holds it', async () => {
    const other = await zetcertLikeProcess();
    root.write('/run/zetcert.lock', `${other.pid}\n`);
    try {
      expect(() => acquireLock()).toThrow(`another zetcert sync is running (pid ${other.pid})`);
    } finally {
      other.kill();
    }
  });
});
