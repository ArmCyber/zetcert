import { existsSync, readFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { snippetContent } from '../../../src/nginx/snippets';
import { setDriverFactory } from '../../../src/dns/index';
import { setLookup } from '../../../src/precheck/lookup';
import { resetExec, setExec } from '../../../src/system/exec';
import { loadState } from '../../../src/system/state';
import { setIsRoot } from '../../../src/system/root';
import { makeCert } from '../certs-helper';
import { fakeSystem, type FakeSystem } from '../fake-certbot';
import { FakeDns } from '../fake-dns';
import { capture, tempRoot, zetcertLikeProcess } from '../helpers';

let root: ReturnType<typeof tempRoot>;
let sys: FakeSystem;
let web: http.Server;
let webAddress = '';

beforeAll(async () => {
  // Plays nginx on port 80: serves the webroot of the current test tree.
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
  sys = fakeSystem(root);
  setExec(sys.exec);
  setIsRoot(true);
  // Every name points at this server, except the ones a test removes.
  setLookup({ addresses: async (name, family) => (family === 4 && !name.startsWith('nodns.') ? ['203.0.113.10'] : []), caa: async () => [] });
  root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
  const placeholder = makeCert({ names: ['zetcert placeholder'] });
  root.write('/var/lib/zetcert/placeholder/fullchain.pem', placeholder.pem);
  root.write('/var/lib/zetcert/placeholder/privkey.pem', placeholder.key);
  root.write('/run/.keep', '');
});
afterEach(() => {
  root.cleanup();
  resetExec();
  setIsRoot(undefined);
  setLookup(undefined);
});

function nginx(servers: string) {
  root.write('/etc/nginx/nginx.conf', `http {\n${servers}\n}\n`);
}
const server = (names: string, cert = 'store') => `  server { listen 443 ssl; server_name ${names}; include /etc/nginx/zetcert/${cert}.conf; }`;

async function sync(...args: string[]) {
  const c = capture();
  const code = await run(['sync', '-y', '--no-color', ...args], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}
const certbotCalls = () => sys.calls.filter((c) => c[0] === 'certbot' && c[1] !== '--version');
/** Whether nginx was reloaded before the first certbot call with this subcommand. */
function reloadBefore(subcommand: string): boolean {
  const reload = sys.calls.findIndex((c) => c[0] === 'sh' && c.at(-1) === 'systemctl reload nginx');
  const certbot = sys.calls.findIndex((c) => c[0] === 'certbot' && c[1] === subcommand);
  return reload !== -1 && certbot !== -1 && reload < certbot;
}
const renewalFile = (cert: string) => readFileSync(root.path(`/etc/letsencrypt/renewal/${cert}.conf`), 'utf8');

describe('sync', () => {
  it('issues a new certificate from a new include, then points the snippet at it and reloads', async () => {
    nginx(server('store.example www.store.example'));
    const r = await sync();
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    expect(r.out).toContain('Created /etc/nginx/zetcert/store.conf (placeholder until it is issued).');
    expect(r.out).toContain('store  new: store.example, www.store.example');
    expect(certbotCalls()).toEqual([
      [
        'certbot', 'certonly', '--non-interactive', '--agree-tos', '--cert-name', 'store',
        '-d', 'store.example', '-d', 'www.store.example', '--key-type', 'ecdsa',
        '--webroot', '-w', '/var/www/html', '--register-unsafely-without-email',
      ],
    ]);
    expect(readFileSync(root.path('/etc/nginx/zetcert/store.conf'), 'utf8')).toBe(snippetContent('store', true));
    // The new server block is live before Let's Encrypt validates it, then again with its certificate.
    expect(sys.shell).toEqual(['nginx -t', 'systemctl reload nginx', 'nginx -t', 'systemctl reload nginx']);
    expect(reloadBefore('certonly')).toBe(true);
    expect(r.out).toContain('Reloaded nginx, so validation sees the new files.');
    expect(loadState().certs.store?.issued).toHaveLength(1);
    expect(r.out).toContain('✓ store: issued (2 names)');
  });

  it('makes no certbot call and no reload when nothing changed', async () => {
    nginx(server('store.example'));
    await sync();
    sys.calls = [];
    sys.shell = [];
    const r = await sync();
    expect(r.code).toBe(0);
    expect(r.out).toContain('store  up to date');
    expect(r.out).toContain('Nothing to do.');
    expect(certbotCalls()).toEqual([]);
    expect(sys.shell).toEqual(['nginx -t']);
  });

  it('adds and removes names with a new certonly, and re-issues with --force', async () => {
    nginx(server('store.example old.store.example'));
    await sync();
    nginx(server('store.example shop.store.example'));
    sys.calls = [];
    const r = await sync();
    expect(r.out).toContain('store  + shop.store.example  - old.store.example');
    expect(certbotCalls()[0]).toEqual(expect.arrayContaining(['-d', 'shop.store.example']));
    expect(certbotCalls()[0]).not.toContain('--force-renewal');
    sys.calls = [];
    await sync('--force');
    expect(certbotCalls()[0]).toContain('--force-renewal');
  });

  it('leaves out names that fail the pre-checks, and records them', async () => {
    nginx(server('store.example nodns.store.example'));
    const r = await sync();
    expect(r.code).toBe(2);
    expect(r.out).toContain('skipped nodns.store.example: no A/AAAA record');
    expect(certbotCalls()[0]).not.toContain('nodns.store.example');
    expect(loadState().certs.store?.skipped.map((s) => [s.name, s.reason])).toEqual([['nodns.store.example', 'no A/AAAA record']]);
  });

  it('fails the whole certificate with --strict', async () => {
    nginx(server('store.example nodns.store.example'));
    const r = await sync('--strict');
    expect(r.code).toBe(2);
    expect(r.err).toContain('store: pre-check failed (--strict): nodns.store.example: no A/AAAA record');
    expect(certbotCalls()).toEqual([]);
  });

  it("retries once without the names Let's Encrypt rejects", async () => {
    nginx(server('store.example broken.store.example'));
    sys.reject.add('broken.store.example');
    const r = await sync('--no-precheck');
    expect(r.code).toBe(2);
    expect(certbotCalls()).toHaveLength(2);
    expect(certbotCalls()[1]).not.toContain('broken.store.example');
    expect(renewalFile('store')).not.toContain('broken.store.example');
    expect(r.err).toContain('skipped store: broken.store.example (dns: DNS problem: NXDOMAIN looking up A for broken.store.example)');
  });

  it('stops before issuing when nginx -t fails', async () => {
    nginx(server('store.example'));
    sys.nginxTestFails = 'always';
    const r = await sync();
    expect(r.code).toBe(1);
    expect(r.err).toContain('nginx -t failed, so nothing was issued');
    expect(certbotCalls()).toEqual([]);
  });

  it('restores the previous files and does not reload again when nginx -t fails afterwards', async () => {
    nginx(server('store.example'));
    sys.nginxTestFails = 'after-first';
    const r = await sync();
    expect(r.code).toBe(1);
    expect(r.err).toContain('nginx -t failed with the new files, so the previous ones are back');
    expect(readFileSync(root.path('/etc/nginx/zetcert/store.conf'), 'utf8')).toBe(snippetContent('store', false));
    // Only the reload before validating: the placeholder snippet passed nginx -t.
    expect(sys.shell).toEqual(['nginx -t', 'systemctl reload nginx', 'nginx -t']);
  });

  it('still runs the deploy commands of issued certificates when nginx -t fails afterwards', async () => {
    nginx(server('store.example'));
    root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\ncerts:\n  store:\n    deploy: ["systemctl reload postfix"]\n`);
    sys.nginxTestFails = 'after-first';
    const r = await sync();
    expect(r.code).toBe(1);
    expect(r.err).toContain('nginx -t failed with the new files');
    // The certificate was issued, so postfix gets it even though nginx keeps the old files.
    expect(sys.shell).toEqual(['nginx -t', 'systemctl reload nginx', 'nginx -t', 'systemctl reload postfix']);
  });

  it('with --dry-run, tests against staging and saves only the new snippets', async () => {
    nginx(server('store.example'));
    const r = await sync('--dry-run');
    expect(r.code).toBe(0);
    expect(certbotCalls()[0]).toContain('--dry-run');
    expect(r.out).toContain('Kept for nginx -t (--dry-run): /etc/nginx/zetcert/store.conf');
    expect(existsSync(root.path('/etc/letsencrypt/live/store'))).toBe(false);
    expect(existsSync(root.path('/etc/nginx/zetcert/_acme.conf'))).toBe(false);
    expect(sys.shell).toEqual(['nginx -t']);
    expect(existsSync(root.path('/var/lib/zetcert/state.json'))).toBe(false);
  });

  it('fixes its own renewal settings with reconfigure', async () => {
    nginx(server('store.example'));
    await sync();
    root.write('/etc/zetcert/config.yml', `webroot: /srv/acme\npublic_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
    sys.calls = [];
    const r = await sync();
    expect(r.out).toContain('renewal settings (certbot reconfigure): webroot_path /var/www/html → /srv/acme');
    expect(certbotCalls()[0]?.slice(0, 2)).toEqual(['certbot', 'reconfigure']);
    expect(r.out).toContain('✓ store: renewal settings updated');
    expect(readFileSync(root.path('/etc/nginx/zetcert/_acme.conf'), 'utf8')).toContain('root /srv/acme;');
    // reconfigure's test renewal validates: the new _acme.conf is live before it.
    expect(r.out).toContain('Reloaded nginx, so validation sees the new files.');
    expect(reloadBefore('reconfigure')).toBe(true);
  });

  it('reloads before validating only when certbot has work', async () => {
    nginx(server('store.example'));
    await sync();
    nginx(`${server('store.example')}\n${server('blog.example', 'blog')}`);
    sys.shell = [];
    const r = await sync('store');
    expect(r.code).toBe(0);
    expect(r.out).not.toContain('so validation sees the new files');
    // The new placeholder snippet is reloaded once, at the end.
    expect(sys.shell).toEqual(['nginx -t', 'nginx -t', 'systemctl reload nginx']);
  });

  it('re-issues with --force-renewal instead of reconfigure before certbot 2.3', async () => {
    nginx(server('store.example'));
    await sync();
    sys.version = '2.2.0';
    root.write('/etc/zetcert/config.yml', `webroot: /srv/acme\npublic_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
    sys.calls = [];
    const r = await sync('--no-precheck');
    expect(r.out).toContain('renewal settings (new certificate): webroot_path /var/www/html → /srv/acme');
    expect(certbotCalls()[0]?.slice(0, 2)).toEqual(['certbot', 'certonly']);
    expect(certbotCalls()[0]).toContain('--force-renewal');
  });

  it('re-issues a staging certificate for production with --force-renewal', async () => {
    nginx(server('store.example'));
    await sync();
    const text = renewalFile('store').replace('https://acme-v02.api.letsencrypt.org/directory', 'https://acme-staging-v02.api.letsencrypt.org/directory');
    root.write('/etc/letsencrypt/renewal/store.conf', text);
    sys.calls = [];
    const r = await sync();
    expect(r.out).toContain('re-issue: the certificate is from the staging server');
    expect(certbotCalls()[0]).toContain('--force-renewal');
  });

  it('never runs reconfigure with --dry-run: certonly --dry-run with the new settings instead', async () => {
    nginx(server('store.example'));
    await sync();
    root.write('/etc/zetcert/config.yml', `webroot: /srv/acme\npublic_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
    sys.calls = [];
    await sync('--dry-run');
    expect(certbotCalls()[0]).toEqual(expect.arrayContaining(['certonly', '--dry-run', '-w', '/srv/acme']));
  });

  it('runs the deploy commands of issued certificates after the reload', async () => {
    nginx(server('store.example'));
    root.write(
      '/etc/zetcert/config.yml',
      `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\ncerts:\n  store:\n    deploy: ["systemctl reload postfix"]\n`,
    );
    await sync();
    expect(sys.shell.slice(-2)).toEqual(['systemctl reload nginx', 'systemctl reload postfix']);
  });

  it('limits the run to the certificates named', async () => {
    nginx(`${server('a.example.com', 'one')}\n${server('b.example.com', 'two')}`);
    const r = await sync('two');
    expect(certbotCalls().map((c) => c[5])).toEqual(['two']);
    expect(r.out).not.toContain('one  new');
    expect((await sync('nope')).err).toContain('no certificate named nope');
  });

  it('refuses while another sync holds the lock', async () => {
    nginx(server('store.example'));
    const other = await zetcertLikeProcess();
    root.write('/run/zetcert.lock', `${other.pid}\n`);
    try {
      const r = await sync();
      expect(r.code).toBe(1);
      expect(r.err).toContain(`another zetcert sync is running (pid ${other.pid})`);
      expect(certbotCalls()).toEqual([]);
    } finally {
      other.kill();
    }
  });

  it('asks before acting and does nothing when declined', async () => {
    nginx(server('store.example'));
    const c = capture({ confirm: false });
    const code = await run(['sync', '--no-color'], c.io);
    expect(code).toBe(1);
    expect(c.stderr()).toContain('nginx -t fails without the snippet of store');
    expect(certbotCalls()).toEqual([]);
  });

  it('issues DNS-validated certificates with the manual hooks, via the account that manages the zone', async () => {
    const dns = new FakeDns();
    dns.zones = { 'cf-main': ['client.example'] };
    setDriverFactory(dns.driver);
    try {
      root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
      nginx(`${server('client.example app.client.example api.eu.client.example', 'wildcard.client.example')}\n${server('store.example')}`);
      const r = await sync();
      expect(r.err).toBe('');
      expect(r.code).toBe(0);
      expect(r.out).toContain('wildcard.client.example  new: client.example, *.client.example, *.eu.client.example (DNS via cf-main)');
      const call = certbotCalls().find((c) => c.includes('wildcard.client.example')) ?? [];
      expect(call).toEqual(
        expect.arrayContaining([
          '--manual',
          '--preferred-challenges',
          'dns',
          '--manual-auth-hook',
          '/usr/local/sbin/zetcert hook auth --cert wildcard.client.example',
          '--manual-cleanup-hook',
          '/usr/local/sbin/zetcert hook cleanup --cert wildcard.client.example',
        ]),
      );
      expect(call).not.toContain('--webroot');
      // The saved hooks now match: nothing to do.
      sys.calls = [];
      expect((await sync()).out).toContain('wildcard.client.example  up to date');
    } finally {
      setDriverFactory(undefined);
    }
  });

  it('fails a DNS certificate without an account and goes on with the others', async () => {
    const dns = new FakeDns();
    setDriverFactory(dns.driver);
    try {
      nginx(`${server('client.example', 'wildcard.client.example')}\n${server('store.example')}`);
      const r = await sync();
      expect(r.code).toBe(2);
      expect(r.out).toContain('wildcard.client.example  failed: no DNS account manages client.example: run zetcert dns add …');
      expect(certbotCalls().map((c) => c[5])).toEqual(['store']);
      root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\ncerts:\n  wildcard.client.example:\n    dns: nope\n`);
      expect((await sync()).out).toContain("failed: the DNS account nope (dns: in the config) doesn't exist: run zetcert dns add nope …");
    } finally {
      setDriverFactory(undefined);
    }
  });

  it('with --no-reload, runs the deploy commands but leaves nginx alone', async () => {
    nginx(server('store.example'));
    root.write('/etc/zetcert/config.yml', `public_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\ncerts:\n  store:\n    deploy: ["systemctl reload postfix"]\n`);
    const r = await sync('--no-reload');
    expect(r.out).toContain('nginx not reloaded (--no-reload).');
    expect(sys.shell).toEqual(['nginx -t', 'nginx -t', 'systemctl reload postfix']);
  });

  it('warns before re-issuing a certificate issued 3 times in the last week', async () => {
    nginx(server('store.example'));
    await sync();
    await sync('--force');
    await sync('--force');
    const r = await sync('--force', '--dry-run');
    expect(r.out).not.toContain('issued 3 times');
    expect((await sync('--force')).out).toContain("warning: issued 3 times in the last 7 days; Let's Encrypt allows 5 per identical name set per week");
  });

  it('deletes _tls.conf with tls: off once nginx no longer includes it, and keeps it while it does', async () => {
    root.write('/etc/nginx/zetcert/_tls.conf', '# old\n');
    root.write('/etc/zetcert/config.yml', `tls: off\npublic_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
    nginx(`  include /etc/nginx/zetcert/_tls.conf;\n${server('store.example')}`);
    let r = await sync();
    expect(r.err).toContain('tls: off, but /etc/nginx/nginx.conf:2 still includes /etc/nginx/zetcert/_tls.conf');
    expect(existsSync(root.path('/etc/nginx/zetcert/_tls.conf'))).toBe(true);
    nginx(server('store.example'));
    r = await sync();
    expect(r.out).toContain('/etc/nginx/zetcert/_tls.conf to delete (tls: off)');
    expect(existsSync(root.path('/etc/nginx/zetcert/_tls.conf'))).toBe(false);
  });

  it('shows unused certificates without failing', async () => {
    nginx(server('store.example'));
    root.write('/etc/nginx/zetcert/leftover.conf', snippetContent('leftover', false));
    const r = await sync();
    expect(r.out).toContain('leftover  unused: no nginx include and not in the config.');
    expect(r.code).toBe(0);
  });

  it("doesn't turn a failed reconfigure into an issuance", async () => {
    nginx(server('store.example www.store.example'));
    await sync();
    root.write('/etc/zetcert/config.yml', `webroot: /srv/acme\npublic_ips: [203.0.113.10]\nprecheck:\n  http_address: ${webAddress}\n`);
    sys.reject.add('www.store.example');
    sys.calls = [];
    const r = await sync();
    expect(r.code).toBe(2);
    expect(certbotCalls().map((c) => c[1])).toEqual(['reconfigure']);
    expect(r.err).toContain("store: certbot reconfigure's test renewal failed, so the renewal settings are unchanged");
    expect(renewalFile('store')).toContain('www.store.example');
  });

  it('maps a rejected wildcard identifier to its wildcard name', async () => {
    const dns = new FakeDns();
    dns.zones = { 'cf-main': ['client.example'] };
    setDriverFactory(dns.driver);
    try {
      root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
      nginx(server('client.example api.eu.client.example', 'wildcard.client.example'));
      sys.reject.add('*.eu.client.example');
      const r = await sync();
      expect(r.code).toBe(2);
      expect(certbotCalls()).toHaveLength(2);
      expect(certbotCalls()[1]).not.toContain('*.eu.client.example');
      expect(loadState().certs['wildcard.client.example']?.skipped.map((x) => x.name)).toEqual(['*.eu.client.example']);
    } finally {
      setDriverFactory(undefined);
    }
  });

  it('fails a wildcard.D certificate rather than dropping D or *.D', async () => {
    const dns = new FakeDns();
    dns.zones = { 'cf-main': ['client.example'] };
    setDriverFactory(dns.driver);
    try {
      root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
      nginx(server('client.example', 'wildcard.client.example'));
      sys.reject.add('*.client.example');
      const r = await sync();
      expect(r.code).toBe(2);
      expect(certbotCalls()).toHaveLength(1);
      expect(r.err).toContain("wildcard.client.example always contains client.example and *.client.example, and Let's Encrypt rejected client.example, *.client.example");
    } finally {
      setDriverFactory(undefined);
    }
  });

  it('says so when certbot keeps a certificate it was asked to renew', async () => {
    nginx(server('store.example'));
    const expiring = makeCert({ names: ['store.example'], notBefore: new Date(Date.now() - 80 * 86_400_000) });
    root.write('/etc/nginx/zetcert/store.conf', snippetContent('store', true));
    root.write('/etc/letsencrypt/live/store/cert.pem', expiring.pem);
    root.write('/etc/letsencrypt/live/store/fullchain.pem', expiring.pem);
    root.write('/etc/letsencrypt/renewal/store.conf', '[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/html,\nkey_type = ecdsa\n[[webroot_map]]\nstore.example = /var/www/html\n');
    const r = await sync();
    expect(r.out).toMatch(/store +renew: it expires \d{4}-\d\d-\d\d and certbot hasn't renewed it/);
    expect(r.err).toContain('store: certbot kept the certificate ("not yet due for renewal"), so nothing changed');
    expect(r.code).toBe(2);
  });

  it('shows the warnings about names, like status', async () => {
    nginx(server('store.example ~^shop[0-9]+$ bad_name.store.example _'));
    const r = await sync('--dry-run');
    expect(r.out).toContain('warning: server_name "~^shop[0-9]+$" at /etc/nginx/nginx.conf:2 skipped: regular expression');
    expect(r.out).toContain('warning: server_name "bad_name.store.example" at /etc/nginx/nginx.conf:2 skipped: not a valid DNS name');
    expect(r.out).not.toContain('server_name "_"');
    expect((await sync('--dry-run', '-v')).out).toContain('server_name "_" at /etc/nginx/nginx.conf:2 skipped: catch-all name');
  });

  it('says when every name was skipped', async () => {
    nginx(server('nodns.store.example'));
    const r = await sync();
    expect(r.out).toContain('skipped: no names left: every name was skipped (see below)');
    expect(r.code).toBe(2);
  });

  it('saves nothing with --dry-run, not even the DNS zones', async () => {
    const dns = new FakeDns();
    dns.zones = { 'cf-main': ['client.example'] };
    setDriverFactory(dns.driver);
    try {
      root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
      nginx(server('client.example', 'wildcard.client.example'));
      expect((await sync('--dry-run')).code).toBe(0);
      expect(existsSync(root.path('/var/lib/zetcert/state.json'))).toBe(false);
    } finally {
      setDriverFactory(undefined);
    }
  });

  it("doesn't check or fail a leftover wildcard snippet", async () => {
    nginx(server('store.example'));
    root.write('/etc/nginx/zetcert/wildcard.client.example.conf', snippetContent('wildcard.client.example', false));
    const r = await sync();
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/wildcard.client.example +unused: /);
    expect(certbotCalls().map((c) => c[5])).toEqual(['store']);
  });
});
