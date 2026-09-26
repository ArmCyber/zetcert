import { chmodSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { snippetContent } from '../../../src/nginx/snippets';
import { setDriverFactory } from '../../../src/dns/index';
import { setLookup } from '../../../src/precheck/lookup';
import { resetExec, setExec } from '../../../src/system/exec';
import { hookScript, launcherScript, setRootUid } from '../../../src/system/install';
import { setIsRoot } from '../../../src/system/root';
import { VERSION } from '../../../src/version';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { FakeDns } from '../fake-dns';
import { capture, tempRoot } from '../helpers';

const WEBROOT = 'authenticator = webroot\nwebroot_path = /var/www/html,\nkey_type = ecdsa\n[[webroot_map]]\nstore.example = /var/www/html';

let root: ReturnType<typeof tempRoot>;
let web: http.Server;
let webAddress = '';
let timerActive = true;

beforeAll(async () => {
  web = http.createServer((req, res) => {
    try {
      res.end(readFileSync(root.path(`/var/www/html${req.url}`)));
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => web.listen(0, '127.0.0.1', r));
  webAddress = `127.0.0.1:${(web.address() as AddressInfo).port}`;
});
afterAll(() => web.close());

beforeEach(() => {
  root = tempRoot();
  timerActive = true;
  setIsRoot(true);
  setRootUid(process.getuid?.() ?? 0);
  setLookup({ addresses: async (_n, family) => (family === 4 ? ['203.0.113.10'] : []), caa: async () => [] });
  setExec(async (command, args) => {
    const ok = (stdout = '') => ({ code: 0, stdout, stderr: '', timedOut: false });
    if (command === 'env') return ok(`${VERSION}\n`);
    if (command === 'systemctl') return timerActive && args[1] === 'certbot.timer' ? ok('active') : { code: 3, stdout: 'inactive', stderr: '', timedOut: false };
    if (command === 'certbot') return ok('certbot 4.0.0\n');
    if (command === 'openssl') return ok('OpenSSL 3.5.7 9 Jun 2026\n');
    return ok();
  });
  root.write('/usr/local/sbin/zetcert', launcherScript());
  root.write('/usr/local/lib/zetcert/zetcert.cjs', '// bundle');
  root.write('/usr/local/lib/zetcert/node', 'node');
  root.write('/usr/local/lib/zetcert/install.json', JSON.stringify({ version: VERSION, npm: '/usr/lib/node_modules/zetcert/dist/zetcert.cjs' }));
  root.write('/usr/lib/node_modules/zetcert/package.json', JSON.stringify({ name: 'zetcert', version: VERSION }));
  root.write('/usr/lib/node_modules/zetcert/dist/zetcert.cjs', '');
  root.write('/etc/letsencrypt/renewal-hooks/deploy/zetcert', hookScript('deploy'));
  root.write('/etc/letsencrypt/renewal-hooks/post/zetcert', hookScript('post'));
  for (const p of [
    '/', '/usr', '/usr/local', '/usr/local/sbin', '/usr/local/sbin/zetcert', '/usr/local/lib', '/usr/local/lib/zetcert',
    '/usr/local/lib/zetcert/zetcert.cjs', '/usr/local/lib/zetcert/node', '/etc', '/etc/letsencrypt',
    '/etc/letsencrypt/renewal-hooks', '/etc/letsencrypt/renewal-hooks/deploy', '/etc/letsencrypt/renewal-hooks/post',
    '/etc/letsencrypt/renewal-hooks/deploy/zetcert', '/etc/letsencrypt/renewal-hooks/post/zetcert',
  ]) {
    chmodSync(root.path(p), 0o755);
  }
  root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
  root.write('/etc/nginx/nginx.conf', 'http {\n  server { listen 80; server_name store.example; include /etc/nginx/zetcert/store.conf; }\n}\n');
  root.write('/etc/nginx/zetcert/store.conf', snippetContent('store', true));
  writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'] }), WEBROOT);
  root.write('/var/www/html/.keep', '');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  setRootUid(0);
  setLookup(undefined);
  resetExec();
});

async function doctor() {
  const c = capture();
  const code = await run(['doctor', '--no-color'], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('doctor', () => {
  it('passes on a healthy server', async () => {
    const r = await doctor();
    expect(r.out).not.toContain('✗');
    expect(r.out).toContain('✓ env -i /usr/local/sbin/zetcert --version works');
    expect(r.out).toContain('✓ /usr/local/sbin/zetcert and the directories above it are root-only');
    expect(r.out).toContain('✓ certbot.timer is active');
    expect(r.out).toContain("✓ store.example: nginx serves the ACME path, DNS points here, CAA allows Let's Encrypt");
    expect(r.out).toMatch(/✓ store: up to date, expires/);
    expect(r.out).toContain('No problems.');
    expect(r.code).toBe(0);
  });

  it('reports the certificates like status', async () => {
    writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'], notBefore: new Date(Date.now() - 86 * 86_400_000) }), WEBROOT);
    const r = await doctor();
    expect(r.out).toMatch(/✗ store: expires \d{4}-\d\d-\d\d \(in 3 days\)/);
    expect(r.code).toBe(1);
  });

  it('warns about a missing or older npm copy, and a hook certbot would skip', async () => {
    root.write('/usr/lib/node_modules/zetcert/package.json', JSON.stringify({ name: 'zetcert', version: '0.0.1' }));
    chmodSync(root.path('/etc/letsencrypt/renewal-hooks/post/zetcert'), 0o644);
    let r = await doctor();
    expect(r.out).toContain(`! the npm copy (0.0.1) is older than the system copy (${VERSION})`);
    expect(r.out).toContain("✗ /etc/letsencrypt/renewal-hooks/post/zetcert isn't executable, so certbot skips it");
    rmSync(root.path('/usr/lib/node_modules/zetcert'), { recursive: true });
    r = await doctor();
    expect(r.out).toContain('the npm copy at /usr/lib/node_modules/zetcert/dist/zetcert.cjs is gone');
  });

  it('checks the DNS accounts and the zones of DNS-validated names', async () => {
    const dns = new FakeDns();
    dns.zones = { 'cf-main': ['client.example'] };
    dns.broken.add('zold');
    setDriverFactory(dns.driver);
    try {
      root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
      root.write('/etc/zetcert/dns/zold.yml', 'driver: cloudflare\ntoken: old\n');
      root.write(
        '/etc/nginx/nginx.conf',
        'http {\n  server { listen 80; server_name store.example; include /etc/nginx/zetcert/store.conf; }\n  server { listen 80; server_name client.example other.invalid; include /etc/nginx/zetcert/foo.conf; }\n}\n',
      );
      root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\ncerts:\n  foo:\n    challenge: dns\n`);
      const r = await doctor();
      expect(r.out).toContain('✓ cf-main (cloudflare): the credentials work');
      expect(r.out).toContain('✗ zold (cloudflare): Invalid access token (9109)');
      expect(r.out).toContain('✓ foo: client.example is in client.example (cf-main)');
      expect(r.out).toContain('✗ foo: no DNS account manages other.invalid');
    } finally {
      setDriverFactory(undefined);
    }
  });

  it('finds the problems', async () => {
    timerActive = false;
    chmodSync(root.path('/usr/local/sbin'), 0o777);
    root.write('/etc/letsencrypt/renewal-hooks/post/zetcert', '#!/bin/sh\necho edited\n');
    root.write('/etc/nginx/nginx.conf', 'http {\n  ssl_stapling on;\n  server { listen 80; server_name store.example ~^x$; include /etc/nginx/zetcert/store.conf; }\n}\n');
    root.write('/usr/lib/node_modules/zetcert/package.json', JSON.stringify({ name: 'zetcert', version: '99.0.0' }));
    const r = await doctor();
    expect(r.code).toBe(1);
    expect(r.out).toContain('✗ /usr/local/sbin/zetcert: /usr/local/sbin isn\'t owned by root, or others than root can write it');
    expect(r.out).toContain('✗ no active certbot timer');
    expect(r.out).toContain('✗ /etc/letsencrypt/renewal-hooks/post/zetcert was changed: run zetcert init');
    expect(r.out).toContain("! /etc/nginx/nginx.conf:2: ssl_stapling on is useless: Let's Encrypt ended OCSP in 2025");
    expect(r.out).toContain('! /etc/nginx/nginx.conf:3: server_name "~^x$" skipped');
    expect(r.out).toContain(`! npm has zetcert 99.0.0, but the system copy is ${VERSION}`);
    expect(r.out).toMatch(/3 problems, 3 warnings\./);
  });
});
