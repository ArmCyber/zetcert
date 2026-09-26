import { afterEach, describe, expect, it } from 'vitest';
import { runDeploy } from '../../../src/cli/nginx';
import { exec, resetExec, setExec, shell, spawnExec } from '../../../src/system/exec';

describe('spawnExec', () => {
  it('captures stdout, stderr and the exit code', async () => {
    const r = await spawnExec('sh', ['-c', 'echo out; echo err >&2; exit 3']);
    expect(r).toEqual({ code: 3, stdout: 'out\n', stderr: 'err\n', timedOut: false });
  });

  it('passes stdin and environment changes', async () => {
    process.env.ZETCERT_TEST_REMOVE = 'x';
    const r = await spawnExec('sh', ['-c', 'cat; echo "$ZETCERT_TEST_ADD${ZETCERT_TEST_REMOVE-unset}"'], {
      input: 'message\n',
      env: { ZETCERT_TEST_ADD: 'added-', ZETCERT_TEST_REMOVE: undefined },
    });
    delete process.env.ZETCERT_TEST_REMOVE;
    expect(r.stdout).toBe('message\nadded-unset\n');
  });

  it('streams output while the command runs', async () => {
    const chunks: string[] = [];
    await spawnExec('sh', ['-c', 'echo a; echo b >&2'], { onOutput: (c) => chunks.push(c) });
    expect(chunks.join('')).toContain('a\n');
    expect(chunks.join('')).toContain('b\n');
  });

  it('stops the command and everything it started after the timeout', async () => {
    const started = Date.now();
    const r = await spawnExec('sh', ['-c', 'sleep 10 & sleep 10; echo late'], { timeoutMs: 200 });
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
    expect(r.stdout).toBe('');
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it('rejects when the command does not exist', async () => {
    await expect(spawnExec('zetcert-no-such-command', [])).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('setExec', () => {
  afterEach(resetExec);

  it('replaces how commands run', async () => {
    const calls: string[][] = [];
    setExec(async (command, args) => {
      calls.push([command, ...args]);
      return { code: 0, stdout: 'fake', stderr: '', timedOut: false };
    });
    expect((await exec('certbot', ['--version'])).stdout).toBe('fake');
    await shell('nginx -t');
    expect(calls).toEqual([['certbot', '--version'], ['sh', '-c', 'nginx -t']]);
  });
});

describe('deploy commands', () => {
  it('are stopped at their time limit and reported', async () => {
    const r = await runDeploy('sleep 10; echo late', 300);
    expect(r).toEqual({ ok: false, output: 'stopped after 0.3 s' });
  });
});
