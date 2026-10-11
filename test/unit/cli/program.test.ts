import { existsSync, rmSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { type Io, run } from '../../../src/cli/program';
import { acmeConfContent, tlsConfContent } from '../../../src/nginx/support';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import type { LatestVersion } from '../../../src/system/update';
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

describe('the update note', () => {
  const NOTE = `\nzetcert 99.0.0 is available (this is ${VERSION}). To upgrade: npm install -g zetcert@latest, then sudo zetcert init\n`;
  const UPDATE_FILE = '/var/lib/zetcert/update.json';

  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => {
    root = tempRoot();
    setIsRoot(true);
    setExec(async (command) => {
      throw new Error(`${command} is not installed`);
    });
    root.write('/etc/zetcert/config.yml', '');
    root.write('/etc/nginx/nginx.conf', 'http { }');
    // What init writes, so that status has nothing to warn about.
    root.write('/etc/nginx/zetcert/_tls.conf', tlsConfContent({}));
    root.write('/etc/nginx/zetcert/_acme.conf', acmeConfContent('/var/www/html'));
  });
  afterEach(() => {
    root.cleanup();
    setIsRoot(undefined);
    resetExec();
  });

  /** A terminal, and npm with `latest` as its newest version: unreachable without one, or a fake of its own. */
  function terminal(latest?: string | LatestVersion, isTTY = true) {
    let all = '';
    let stderr = '';
    let asked = 0;
    const io: Io = {
      ...capture().io,
      stdout: { write: (text: string) => (all += text) },
      stderr: {
        write: (text: string) => {
          all += text;
          stderr += text;
        },
        isTTY,
      },
      latestVersion: async (signal) => {
        asked++;
        if (typeof latest === 'function') return latest(signal);
        if (latest === undefined) throw new Error('getaddrinfo ENOTFOUND registry.npmjs.org');
        return latest;
      },
    };
    return { io, all: () => all, stderr: () => stderr, asked: () => asked };
  }

  it('follows the output, on stderr, when npm has a newer version', async () => {
    const t = terminal('99.0.0');
    expect(await run(['--no-color'], t.io)).toBe(0);
    expect(t.stderr()).toBe(NOTE);
    expect(t.all()).toMatch(/^No certificates/);
    expect(t.all().endsWith(NOTE)).toBe(true);
  });

  it('is dimmed on a colour terminal', async () => {
    const t = terminal('99.0.0');
    await run(['status'], t.io);
    expect(t.stderr()).toBe(`\n\x1b[2m${NOTE.trim()}\x1b[0m\n`);
  });

  it('is not shown when this is the latest version', async () => {
    const t = terminal(VERSION);
    expect(await run(['status'], t.io)).toBe(0);
    expect(t.stderr()).toBe('');
    expect(t.asked()).toBe(1);
  });

  it('asks npm once a day, and shows the note every time', async () => {
    const t = terminal('99.0.0');
    await run(['status', '--no-color'], t.io);
    await run(['dns', 'list', '--no-color'], t.io);
    expect(t.stderr()).toBe(NOTE + NOTE);
    expect(t.asked()).toBe(1);
    expect(existsSync(root.path(UPDATE_FILE))).toBe(true);
  });

  it("shows nothing when npm can't be reached, and asks again the next time", async () => {
    const t = terminal();
    expect(await run(['status'], t.io)).toBe(0);
    expect(await run(['status'], t.io)).toBe(0);
    expect(t.stderr()).toBe('');
    expect(t.asked()).toBe(2);
    expect(existsSync(root.path(UPDATE_FILE))).toBe(false);
  });

  it("doesn't change the exit code", async () => {
    rmSync(root.path('/etc/nginx/nginx.conf'));
    const t = terminal('99.0.0');
    expect(await run(['status', '--check', '--no-color'], t.io)).toBe(2);
    expect(t.stderr()).toMatch(/^error: .*nginx\.conf/);
    expect(t.stderr().endsWith(NOTE)).toBe(true);
  });

  it('is not shown after a command that stops with an error, which also stops the request', async () => {
    let signal: AbortSignal | undefined;
    const t = terminal((s) => {
      signal = s;
      return new Promise<string>(() => {});
    });
    expect(await run(['status', 'nope', '--no-color'], t.io)).toBe(1);
    expect(t.stderr()).toMatch(/^error: no certificate named nope.*\n$/);
    expect(signal?.aborted).toBe(true);
  });

  it.each<[string, string[], (() => void)?, boolean?]>([
    ['without a terminal on stderr', ['status'], undefined, false],
    ['with --json', ['status', '--json']],
    ['with -q', ['status', '-q']],
    ['before init has run', ['status'], () => rmSync(root.path('/etc/zetcert/config.yml'))],
    ['for init', ['init', '-y']],
    ['for uninstall', ['uninstall', '-y']],
    ['for the certbot hooks', ['hook', 'post']],
  ])('neither asks npm nor shows a note %s', async (_when, argv, prepare, isTTY) => {
    prepare?.();
    const t = terminal('99.0.0', isTTY);
    await run(argv, { ...t.io, initEnv: { bundle: '/opt/zetcert.cjs', node: '/usr/bin/node', argv } });
    expect(t.asked()).toBe(0);
    expect(t.stderr()).not.toContain('is available');
    expect(existsSync(root.path(UPDATE_FILE))).toBe(false);
  });
});
