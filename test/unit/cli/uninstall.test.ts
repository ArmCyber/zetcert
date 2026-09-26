import { existsSync, readFileSync, rmSync, statSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { hookScript, launcherScript } from '../../../src/system/install';
import { setIsRoot } from '../../../src/system/root';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  root.write('/etc/zetcert/config.yml', '');
  root.write('/usr/local/sbin/zetcert', launcherScript());
  root.write('/usr/local/lib/zetcert/zetcert.cjs', '');
  root.write('/usr/local/lib/zetcert/install.json', '{}');
  root.write('/etc/letsencrypt/renewal-hooks/deploy/zetcert', hookScript('deploy'));
  root.write('/etc/letsencrypt/renewal-hooks/post/zetcert', hookScript('post'));
  root.write('/etc/nginx/zetcert/store.conf', 'snippet');
  writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'] }), 'authenticator = webroot');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
});

async function uninstall(...args: string[]) {
  const c = capture();
  const code = await run(['uninstall', '-y', ...args], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('uninstall', () => {
  it('removes the system copy, launcher and hooks, and leaves a plain deploy hook', async () => {
    const r = await uninstall();
    expect(r.code).toBe(0);
    for (const p of ['/usr/local/lib/zetcert', '/usr/local/sbin/zetcert', '/etc/letsencrypt/renewal-hooks/deploy/zetcert', '/etc/letsencrypt/renewal-hooks/post/zetcert']) {
      expect(existsSync(root.path(p)), p).toBe(false);
    }
    const plain = root.path('/etc/letsencrypt/renewal-hooks/deploy/nginx-reload');
    expect(readFileSync(plain, 'utf8')).toContain('\nnginx -t && systemctl reload nginx\n');
    expect(statSync(plain).mode & 0o777).toBe(0o755);
    for (const p of ['/etc/zetcert/config.yml', '/etc/nginx/zetcert/store.conf', '/etc/letsencrypt/live/store/cert.pem']) {
      expect(existsSync(root.path(p)), p).toBe(true);
    }
    expect(r.out).toContain('npm uninstall -g zetcert');
  });

  it('works without a config, when init stopped before writing it', async () => {
    for (const p of ['/etc/zetcert/config.yml', '/etc/letsencrypt/renewal-hooks/deploy/zetcert', '/etc/letsencrypt/renewal-hooks/post/zetcert']) {
      rmSync(root.path(p));
    }
    const r = await uninstall();
    expect(r.code).toBe(0);
    expect(existsSync(root.path('/usr/local/sbin/zetcert'))).toBe(false);
    expect(existsSync(root.path('/usr/local/lib/zetcert'))).toBe(false);
    // zetcert's hook was never installed, so a plain one would take over nothing.
    expect(existsSync(root.path('/etc/letsencrypt/renewal-hooks/deploy/nginx-reload'))).toBe(false);
  });

  it('lists the deploy commands that stop running', async () => {
    root.write('/etc/zetcert/config.yml', 'certs:\n  mail:\n    names: [mail.example.com]\n    deploy: ["systemctl reload postfix dovecot"]\n');
    const r = await uninstall();
    expect(r.code).toBe(0);
    expect(r.err).toContain('these deploy commands stop running after renewals');
    expect(r.err).toContain('  mail: systemctl reload postfix dovecot');
  });

  it('refuses while DNS-validated certificates renew through zetcert, unless --force', async () => {
    writeCertbotCert(root.write, 'wildcard.client.example', makeCert({ names: ['client.example'] }), 'authenticator = manual\nmanual_auth_hook = /usr/local/sbin/zetcert hook auth --cert wildcard.client.example');
    const r = await uninstall();
    expect(r.code).toBe(1);
    expect(r.err).toContain('renew through zetcert\'s hooks: wildcard.client.example');
    expect(existsSync(root.path('/usr/local/sbin/zetcert'))).toBe(true);
    expect((await uninstall('--force')).code).toBe(0);
  });
});
