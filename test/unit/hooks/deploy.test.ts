import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
let shell: string[];
let failing: Set<string>;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  shell = [];
  failing = new Set();
  setExec(async (_command, args) => {
    const line = args[1] ?? '';
    shell.push(line);
    return failing.has(line) ? { code: 1, stdout: '', stderr: `${line}: failed`, timedOut: false } : { code: 0, stdout: '', stderr: '', timedOut: false };
  });
  root.write('/etc/zetcert/config.yml', 'certs:\n  mail:\n    deploy: ["systemctl reload postfix", "systemctl reload dovecot"]\n');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  resetExec();
  delete process.env.ZETCERT_SYNC;
  delete process.env.RENEWED_LINEAGE;
});

async function hook(kind: string, env: Record<string, string>) {
  Object.assign(process.env, env);
  const c = capture();
  const code = await run(['hook', kind], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('hook deploy', () => {
  it('tests and reloads nginx, then runs the deploy commands of the renewed certificate', async () => {
    const r = await hook('deploy', { RENEWED_LINEAGE: '/etc/letsencrypt/live/mail' });
    expect(r.code).toBe(0);
    expect(shell).toEqual(['nginx -t', 'systemctl reload nginx', 'systemctl reload postfix', 'systemctl reload dovecot']);
  });

  it('does nothing during sync', async () => {
    const r = await hook('deploy', { RENEWED_LINEAGE: '/etc/letsencrypt/live/mail', ZETCERT_SYNC: '1' });
    expect(r.code).toBe(0);
    expect(shell).toEqual([]);
  });

  it("doesn't reload when nginx -t fails, still runs the deploy commands, and fails", async () => {
    failing.add('nginx -t');
    failing.add('systemctl reload dovecot');
    const r = await hook('deploy', { RENEWED_LINEAGE: '/etc/letsencrypt/live/mail' });
    expect(r.code).toBe(1);
    expect(shell).toEqual(['nginx -t', 'systemctl reload postfix', 'systemctl reload dovecot']);
    expect(r.err).toContain('mail: nginx -t failed, so nginx still serves the old certificate');
    expect(r.err).toContain('mail: deploy command failed: systemctl reload dovecot');
  });

  it('still tests and reloads nginx with a broken config, and fails', async () => {
    root.write('/etc/zetcert/config.yml', 'bogus: 1\n');
    const r = await hook('deploy', { RENEWED_LINEAGE: '/etc/letsencrypt/live/mail' });
    expect(r.code).toBe(1);
    expect(shell).toEqual(['nginx -t', 'systemctl reload nginx']);
    expect(r.err).toContain("zetcert uses the default nginx commands, and can't run mail's deploy commands");
  });

  it('ignores --config: the hooks always use the default path', async () => {
    const c = capture();
    process.env.RENEWED_LINEAGE = '/etc/letsencrypt/live/mail';
    await run(['hook', 'deploy', '--config', '/nowhere.yml'], c.io);
    expect(shell).toContain('systemctl reload postfix');
  });
});

describe('hook post', () => {
  it('does nothing during sync', async () => {
    expect((await hook('post', { ZETCERT_SYNC: '1' })).code).toBe(0);
    expect(shell).toEqual([]);
  });
});
