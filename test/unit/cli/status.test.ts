import { rmSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import tls from 'node:tls';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { snippetContent } from '../../../src/nginx/snippets';
import { acmeConfContent, tlsConfContent } from '../../../src/nginx/support';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { capture, tempRoot } from '../helpers';

const DAY = 86_400_000;
const WEBROOT = (names: string[]) =>
  `authenticator = webroot\nwebroot_path = /var/www/html,\nserver = https://acme-v02.api.letsencrypt.org/directory\nkey_type = ecdsa\n[[webroot_map]]\n${names
    .map((n) => `${n} = /var/www/html`)
    .join('\n')}`;

let root: ReturnType<typeof tempRoot>;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  setExec(async (command) => {
    if (command === 'certbot') return { code: 0, stdout: 'certbot 4.0.0\n', stderr: '', timedOut: false };
    throw new Error(`unexpected command ${command}`);
  });
});
let server: tls.Server | undefined;
afterEach(() => {
  server?.close();
  server = undefined;
  root.cleanup();
  setIsRoot(undefined);
  resetExec();
});

/**
 * A server with store issued and up to date, plus whatever the test adds. A local TLS server
 * stands in for nginx and serves the certificate (or `served`, to test a mismatch).
 */
async function setup(options: { extraServers?: string; config?: string; notBefore?: Date; days?: number; served?: 'other' } = {}) {
  const names = ['store.example', 'www.store.example'];
  const cert = makeCert({ names, notBefore: options.notBefore ?? new Date(Date.now() - 10 * DAY), days: options.days ?? 90 });
  const servedCert = options.served === 'other' ? makeCert({ names, subject: '' }) : cert;
  server?.close();
  server = tls.createServer({ cert: servedCert.pem, key: servedCert.key });
  await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  root.write('/etc/zetcert/config.yml', options.config ?? 'email: ops@example.com\n');
  root.write(
    '/etc/nginx/nginx.conf',
    `http {
  server {
    listen 127.0.0.1:${port} ssl;
    server_name store.example www.store.example _;
    include /etc/nginx/zetcert/store.conf;
  }
${options.extraServers ?? ''}
}
`,
  );
  root.write('/etc/nginx/zetcert/store.conf', snippetContent('store', true));
  // What init writes.
  root.write('/etc/nginx/zetcert/_tls.conf', tlsConfContent({}));
  root.write('/etc/nginx/zetcert/_acme.conf', acmeConfContent('/var/www/html'));
  writeCertbotCert(root.write, 'store', cert, WEBROOT(names));
}

async function status(...args: string[]) {
  const c = capture();
  const code = await run(['status', '--no-color', ...args], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('status', () => {
  it('shows an up-to-date certificate', async () => {
    await setup();
    const r = await status();
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/^CERTIFICATE +KIND +VALIDATION +NAMES +EXPIRES +STATE\nstore +regular +http +2 +\d{4}-\d\d-\d\d \(79d\) +ok\n/);
    expect(r.out).toContain('store.example      /etc/nginx/nginx.conf:4');
    expect(r.err).toBe('');
    expect((await status('--check')).code).toBe(0);
  });

  it('shows pending changes as a warning', async () => {
    await setup({ extraServers: '  server { listen 80; server_name shop.store.example; include /etc/nginx/zetcert/store.conf; }' });
    const r = await status();
    expect(r.out).toMatch(/store .* pending changes/);
    expect(r.out).toContain('shop.store.example  /etc/nginx/nginx.conf:7 (not in the certificate yet)');
    expect(r.out).toContain('pending: + shop.store.example');
    expect((await status('--check')).code).toBe(1);
  });

  it('flags a new certificate still on the placeholder as critical', async () => {
    await setup({ extraServers: '  server { listen 443 ssl; server_name client.example; include /etc/nginx/zetcert/client.conf; }' });
    root.write('/etc/nginx/zetcert/client.conf', snippetContent('client', false));
    const r = await status('--check');
    expect(r.out).toMatch(/client +regular +http +1 +— +placeholder/);
    expect(r.out).toContain('critical: nginx uses the placeholder certificate');
    expect(r.code).toBe(2);
  });

  it('flags a failing renewal and an expiring certificate as critical', async () => {
    await setup({ notBefore: new Date(Date.now() - 70 * DAY) });
    let r = await status('--check');
    expect(r.out).toMatch(/store .* not renewing/);
    expect(r.code).toBe(2);
    await setup({ notBefore: new Date(Date.now() - 85 * DAY) });
    r = await status('--check');
    expect(r.out).toMatch(/store .* expiring/);
    expect(r.out).toMatch(/critical: expires \d{4}-\d\d-\d\d \(in 4 days\)/);
  });

  it('lists skipped names from the last sync with their reason', async () => {
    await setup();
    root.write(
      '/var/lib/zetcert/state.json',
      JSON.stringify({ certs: { store: { skipped: [{ name: 'old.store.example', reason: 'no A/AAAA record', at: '2026-09-25T00:00:00Z' }], issued: [] } } }),
    );
    const r = await status('--check');
    expect(r.out).toContain('skipped by the last sync: old.store.example (no A/AAAA record)');
    expect(r.code).toBe(1);
  });

  it('lists silently skipped server names only with -v', async () => {
    await setup();
    expect((await status()).out).not.toContain('"_"');
    expect((await status('-v')).out).toContain('skipped: server_name "_" at /etc/nginx/nginx.conf:4: catch-all name');
  });

  it('shows one certificate, and refuses unknown names', async () => {
    await setup({ config: 'certs:\n  mail:\n    names: [mail.example.com]\n' });
    const r = await status('mail');
    expect(r.out).not.toContain('CERTIFICATE');
    expect(r.out).toContain('mail.example.com  config');
    const unknown = await status('nope');
    expect(unknown.code).toBe(1);
    expect(unknown.err).toContain('no certificate named nope');
  });

  it('prints JSON with --json', async () => {
    await setup();
    const r = await status('--json', '--check');
    const json = JSON.parse(r.out);
    expect(json.initialized).toBe(true);
    expect(json.check).toBe(0);
    expect(json.certificates[0]).toMatchObject({
      name: 'store',
      kind: 'regular',
      validation: 'http',
      names: [
        { name: 'store.example', sources: [{ type: 'nginx', raw: 'store.example', file: '/etc/nginx/nginx.conf', line: 4 }] },
        { name: 'www.store.example' },
      ],
      certificate: { names: ['store.example', 'www.store.example'], staging: false },
      pending: { action: 'none', snippet: 'ok' },
      problems: [],
    });
  });

  it('shows leftover snippets as unused, without warnings', async () => {
    await setup();
    root.write('/etc/nginx/zetcert/wildcard.client.example.conf', snippetContent('wildcard.client.example', false));
    root.write('/etc/nginx/zetcert/old.conf', snippetContent('old', true));
    writeCertbotCert(root.write, 'old', makeCert({ names: ['old.store.example'] }), WEBROOT(['old.store.example']));
    const r = await status('--check');
    expect(r.out).toMatch(/old +regular +http +0 .* unused/);
    expect(r.out).toMatch(/wildcard.client.example +wildcard +dns +2 +— +unused/);
    expect(r.code).toBe(0);
  });

  it('shows outdated support files as pending', async () => {
    await setup();
    root.write('/etc/nginx/zetcert/_acme.conf', '# old webroot\n');
    rmSync(root.path('/etc/nginx/zetcert/_tls.conf'));
    const r = await status('--check');
    expect(r.err).toContain('/etc/nginx/zetcert/_acme.conf to update: sudo zetcert sync does it');
    expect(r.err).toContain('/etc/nginx/zetcert/_tls.conf to create');
    expect(r.code).toBe(1);
  });

  it('shows the >25 names warning once', async () => {
    const many = Array.from({ length: 26 }, (_, i) => `n${i}.store.example`).join(' ');
    await setup({ extraServers: `  server { listen 80; server_name ${many}; include /etc/nginx/zetcert/store.conf; }` });
    const r = await status('--check');
    expect(r.out.match(/more than 25/g)).toHaveLength(1);
  });

  it("says it can't check when nginx doesn't answer, instead of a wrong certificate", async () => {
    await setup();
    server?.close();
    server = undefined;
    const r = await status('--check');
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/store .* can't check what nginx serves/);
  });

  it('warns when the npm copy is newer than the system copy', async () => {
    await setup();
    root.write('/usr/local/lib/zetcert/install.json', '{"version": "0.1.0", "npm": "/usr/lib/node_modules/zetcert/dist/zetcert.cjs"}');
    root.write('/usr/lib/node_modules/zetcert/dist/zetcert.cjs', '');
    root.write('/usr/lib/node_modules/zetcert/package.json', '{"name": "zetcert", "version": "0.2.0"}');
    expect((await status()).err).toContain('npm has zetcert 0.2.0, but the system copy is 0.1.0: run sudo zetcert init to upgrade it');
  });

  it('works before init with the defaults, and says so', async () => {
    root.write('/etc/nginx/nginx.conf', 'http { }');
    const r = await status();
    expect(r.code).toBe(0);
    expect(r.err).toContain("zetcert init hasn't run yet");
    expect(r.out).toContain('No certificates');
  });

  it('fails when the nginx config is broken; --check calls that critical', async () => {
    await setup();
    root.write('/etc/nginx/nginx.conf', 'http {');
    expect((await status()).code).toBe(1);
    const r = await status('--check');
    expect(r.code).toBe(2);
    expect(r.err).toContain('/etc/nginx/nginx.conf:1: unexpected end of file');
  });

  it('exits 2 with --check whenever the check can\'t run', async () => {
    await setup();
    expect((await status('--check', 'nope')).code).toBe(2);
    setIsRoot(false);
    expect((await status('--check')).code).toBe(2);
    expect((await status()).code).toBe(1);
    setIsRoot(true);
    root.write('/etc/zetcert/config.yml', 'key_type: dsa\n');
    expect((await status('--check')).code).toBe(2);
  });

  it('flags a missing include file as critical', async () => {
    await setup({ extraServers: '  include /etc/nginx/gone.conf;' });
    const r = await status('--check');
    expect(r.code).toBe(2);
    expect(r.err).toContain("the included file /etc/nginx/gone.conf doesn't exist, so nginx -t fails");
  });

  it('flags nginx serving another certificate as critical', async () => {
    await setup({ served: 'other' });
    const r = await status('--check');
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/store .* wrong certificate served/);
    expect(r.out).toMatch(/critical: nginx serves a different certificate for store.example on 127.0.0.1:\d+ \(\/etc\/nginx\/nginx.conf:3\): one for store.example, www.store.example, expiring/);
  });
});
