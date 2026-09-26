import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { setIsRoot } from '../../../src/system/root';
import { VERSION } from '../../../src/version';
import { capture, tempRoot } from '../helpers';

describe('CLI skeleton', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => {
    root = tempRoot();
    setIsRoot(true);
  });
  afterEach(() => {
    root.cleanup();
    setIsRoot(undefined);
  });

  it('prints the version with --version', async () => {
    const c = capture();
    expect(await run(['--version'], c.io)).toBe(0);
    expect(c.stdout()).toBe(`${VERSION}\n`);
  });

  it('shows help with -h without needing root', async () => {
    setIsRoot(false);
    const c = capture();
    expect(await run(['-h'], c.io)).toBe(0);
    expect(c.stdout()).toContain('Usage: zetcert');
    expect(c.stdout()).toContain('--config <path>');
  });

  it('refuses to run commands without root', async () => {
    setIsRoot(false);
    root.write('/usr/local/sbin/zetcert', '#!/bin/sh\n');
    const c = capture();
    expect(await run(['status'], c.io)).toBe(1);
    expect(c.stderr()).toContain('must run as root: sudo zetcert');
  });

  it('points to init, without sudo, before zetcert is set up', async () => {
    setIsRoot(false);
    const c = capture();
    expect(await run(['status'], c.io)).toBe(1);
    expect(c.stderr()).toContain("zetcert isn't set up yet: run zetcert init as your normal user, without sudo");
    const check = capture();
    expect(await run(['status', '--check'], check.io)).toBe(2);
  });

  it('runs status without a command, and needs init for the other commands', async () => {
    root.write('/etc/nginx/nginx.conf', 'http { }');
    const c = capture();
    expect(await run(['--no-color'], c.io)).toBe(0);
    expect(c.stdout()).toContain('No certificates');
    const sync = capture();
    expect(await run(['sync'], sync.io)).toBe(1);
    expect(sync.stderr()).toContain('run zetcert init first');
  });

  it('shows only warnings and errors with -q', async () => {
    root.write('/etc/nginx/nginx.conf', 'http { }');
    root.write('/etc/zetcert/config.yml', '');
    const c = capture();
    expect(await run(['status', '-q'], c.io)).toBe(0);
    expect(c.stdout()).toBe('');
  });

  it('writes errors without colour codes with --no-color, even on a terminal', async () => {
    const c = capture();
    const tty = { ...c.io, stdout: { write: c.io.stdout?.write ?? (() => true), isTTY: true }, stderr: { write: c.io.stderr?.write ?? (() => true), isTTY: true } };
    await run(['status', 'nope', '--no-color'], tty as typeof c.io);
    expect(c.stderr()).not.toContain('\x1b[');
  });

  it('rejects unknown options with exit code 1', async () => {
    const c = capture();
    expect(await run(['status', '--bogus'], c.io)).toBe(1);
    expect(c.stderr()).toContain("unknown option '--bogus'");
  });
});
