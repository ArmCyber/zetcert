import { existsSync, readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { readAccounts } from '../../../src/certbot/reader';
import { checkAddresses, checkCaa, checkHttp } from '../../../src/precheck/checks';
import { precheckNames } from '../../../src/precheck/index';
import { type CaaEntry, caaEntry, type Lookup } from '../../../src/precheck/lookup';
import { tempRoot } from '../helpers';

function fakeLookup(a: Record<string, string[]>, caa: Record<string, CaaEntry[]> = {}): Lookup {
  return {
    async addresses(name, family) {
      return (a[name] ?? []).filter((ip) => (family === 4 ? !ip.includes(':') : ip.includes(':')));
    },
    async caa(name) {
      return caa[name] ?? [];
    },
  };
}
const issue = (value: string, tag = 'issue', critical = 0): CaaEntry => ({ critical, tag, value });

describe('DNS check', () => {
  const lookup = fakeLookup({
    'ok.example.com': ['203.0.113.10', '2001:db8::1'],
    'other.example.com': ['203.0.113.10', '198.51.100.4'],
    'cf.example.com': ['104.16.1.1'],
  });

  it('passes when every address is this server', async () => {
    expect(await checkAddresses('ok.example.com', ['203.0.113.10', '2001:db8::1'], lookup)).toEqual({ ok: true, warnings: [] });
  });

  it('fails without records or with an address elsewhere', async () => {
    expect(await checkAddresses('none.example.com', ['203.0.113.10'], lookup)).toMatchObject({ ok: false, reason: 'no A/AAAA record' });
    expect(await checkAddresses('other.example.com', ['203.0.113.10'], lookup)).toMatchObject({
      ok: false,
      reason: "points to 198.51.100.4, which isn't this server (203.0.113.10)",
    });
  });

  it('allows Cloudflare-proxied addresses with a warning', async () => {
    const r = await checkAddresses('cf.example.com', ['203.0.113.10'], lookup);
    expect(r.ok).toBe(true);
    expect(r.warnings).toEqual(['cf.example.com is proxied through Cloudflare (104.16.1.1)']);
  });

  it('compares IPv6 addresses, not their spelling', async () => {
    const v6 = fakeLookup({ 'v6.example.com': ['2001:db8::1'] });
    expect((await checkAddresses('v6.example.com', ['203.0.113.10', '2001:DB8:0:0::1'], v6)).ok).toBe(true);
  });

  it('only warns when no public IPv4 is known', async () => {
    const r = await checkAddresses('other.example.com', [], lookup);
    expect(r.ok).toBe(true);
    expect(r.warnings[0]).toMatch(/set public_ips in the config/);
  });
});

describe('caaEntry', () => {
  it('reads records from Node 20 and from newer Node, which adds type', () => {
    expect(caaEntry({ critical: 0, issue: 'letsencrypt.org' })).toEqual({ critical: 0, tag: 'issue', value: 'letsencrypt.org' });
    expect(caaEntry({ critical: 128, type: 'CAA', issuewild: ';' })).toEqual({ critical: 128, tag: 'issuewild', value: ';' });
  });
});

describe('CAA check', () => {
  const account = 'https://acme-v02.api.letsencrypt.org/acme/acct/123';

  it('passes without CAA records anywhere', async () => {
    expect((await checkCaa('a.b.example.com', 'http-01', [], fakeLookup({}))).ok).toBe(true);
  });

  it('uses the closest record set, climbing to parents', async () => {
    const lookup = fakeLookup({}, { 'example.com': [issue('letsencrypt.org')], 'b.example.com': [issue('ca.example')] });
    expect(await checkCaa('a.b.example.com', 'http-01', [], lookup)).toMatchObject({
      ok: false,
      reason: expect.stringContaining('the CAA records of b.example.com don\'t allow Let\'s Encrypt'),
    });
    expect((await checkCaa('a.c.example.com', 'http-01', [], lookup)).ok).toBe(true);
  });

  it('lets issuewild decide for wildcards when there is one', async () => {
    const lookup = fakeLookup({}, { 'example.com': [issue('letsencrypt.org'), issue(';', 'issuewild')] });
    expect((await checkCaa('www.example.com', 'dns-01', [], lookup)).ok).toBe(true);
    expect((await checkCaa('*.example.com', 'dns-01', [], lookup)).ok).toBe(false);
    const issueOnly = fakeLookup({}, { 'example.com': [issue('letsencrypt.org')] });
    expect((await checkCaa('*.example.com', 'dns-01', [], issueOnly)).ok).toBe(true);
  });

  it('checks validationmethods and accounturi', async () => {
    const lookup = fakeLookup({}, { 'example.com': [issue(`letsencrypt.org; validationmethods=dns-01; accounturi=${account}`)] });
    expect((await checkCaa('example.com', 'dns-01', [account], lookup)).ok).toBe(true);
    expect((await checkCaa('example.com', 'http-01', [account], lookup)).ok).toBe(false);
    expect((await checkCaa('example.com', 'dns-01', ['https://other/acct/1'], lookup)).ok).toBe(false);
    expect((await checkCaa('example.com', 'dns-01', [], lookup)).ok).toBe(false);
  });

  it('ignores iodef-only record sets and refuses unknown critical properties', async () => {
    expect((await checkCaa('example.com', 'http-01', [], fakeLookup({}, { 'example.com': [issue('mailto:a@b.c', 'iodef')] }))).ok).toBe(true);
    expect(
      (await checkCaa('example.com', 'http-01', [], fakeLookup({}, { 'example.com': [issue('letsencrypt.org'), issue('x', 'future', 128)] }))).reason,
    ).toMatch(/critical property/);
  });
});

describe('local HTTP check', () => {
  let root: ReturnType<typeof tempRoot>;
  let server: http.Server;
  let address = '';
  beforeAll(async () => {
    // Plays nginx: serves the webroot for good names, redirects for others.
    server = http.createServer((req, res) => {
      const host = req.headers.host ?? '';
      if (host === 'redirect.example.com') {
        res.writeHead(301, { Location: `https://${host}${req.url}` }).end();
        return;
      }
      try {
        res.end(readFileSync(root.path(`/var/www/html${req.url}`)));
      } catch {
        res.writeHead(404).end('not found');
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    address = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => server.close());
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('passes when nginx serves the token, and removes it', async () => {
    expect(await checkHttp('good.example.com', '/var/www/html', address)).toEqual({ ok: true, warnings: [] });
    expect(existsSync(root.path('/var/www/html/.well-known'))).toBe(false);
  });

  it('fails on a redirect, with the _acme.conf hint', async () => {
    const r = await checkHttp('redirect.example.com', '/var/www/html', address);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/redirects \/.well-known\/acme-challenge\/ to https:\/\/redirect.example.com.*include \/etc\/nginx\/zetcert\/_acme.conf;/);
  });

  it('fails when nginx serves another directory', async () => {
    expect((await checkHttp('good.example.com', '/srv/other', address)).reason).toBe('nginx answered HTTP 404 for /.well-known/acme-challenge/ (webroot /srv/other)');
  });

  it('creates its directories with 0755 whatever the umask, and removes them', async () => {
    const umask = process.umask(0o027);
    try {
      const modes: number[] = [];
      const spy = http.createServer((req, res) => {
        modes.push(statSync(root.path('/var/www/html/.well-known')).mode & 0o777, statSync(root.path('/var/www/html/.well-known/acme-challenge')).mode & 0o777);
        res.end(readFileSync(root.path(`/var/www/html${req.url}`)));
      });
      await new Promise<void>((r) => spy.listen(0, '127.0.0.1', r));
      const r = await checkHttp('good.example.com', '/var/www/html', `127.0.0.1:${(spy.address() as AddressInfo).port}`);
      spy.close();
      expect(r.ok).toBe(true);
      expect(modes).toEqual([0o755, 0o755]);
      expect(existsSync(root.path('/var/www'))).toBe(false);
    } finally {
      process.umask(umask);
    }
  });

  it("doesn't hang when the connection closes during the answer", async () => {
    const broken = http.createServer((_req, res) => {
      res.writeHead(200, { 'Transfer-Encoding': 'chunked' });
      res.write('partial');
      setTimeout(() => res.socket?.destroy(), 20);
    });
    await new Promise<void>((r) => broken.listen(0, '127.0.0.1', r));
    const started = Date.now();
    const r = await checkHttp('good.example.com', '/var/www/html', `127.0.0.1:${(broken.address() as AddressInfo).port}`, 2000);
    broken.close();
    expect(r.ok).toBe(false);
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it('creates a missing webroot like certbot does, and removes it again', async () => {
    const r = await checkHttp('good.example.com', '/srv/acme/root', address);
    expect(r.reason).toBe('nginx answered HTTP 404 for /.well-known/acme-challenge/ (webroot /srv/acme/root)');
    expect(existsSync(root.path('/srv'))).toBe(false);
  });

  it('fails when nothing listens', async () => {
    expect((await checkHttp('good.example.com', '/var/www/html', '127.0.0.1:1')).reason).toMatch(/can't reach nginx at 127.0.0.1:1/);
  });

  it('runs every check per name and stops at the first failure', async () => {
    const lookup = fakeLookup({ 'good.example.com': ['203.0.113.10'], 'redirect.example.com': ['203.0.113.10'] });
    const results = await precheckNames(['good.example.com', 'missing.example.com', 'redirect.example.com'], 'http', {
      webroot: '/var/www/html',
      httpAddress: address,
      publicIps: ['203.0.113.10'],
      accountUris: [],
      lookup,
    });
    expect(results.map((r) => [r.name, r.ok, r.reason?.slice(0, 20) ?? null])).toEqual([
      ['good.example.com', true, null],
      ['missing.example.com', false, 'no A/AAAA record'],
      ['redirect.example.com', false, 'nginx redirects /.we'],
    ]);
  });

  it("reads certbot's account URIs", () => {
    root.write('/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/abc123/regr.json', '{"body": {}, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/1"}');
    root.write('/etc/letsencrypt/accounts/pebble:14000/dir/def456/regr.json', '{"body": {}, "uri": "https://pebble:14000/my-account/1"}');
    expect(Object.fromEntries(readAccounts())).toEqual({
      abc123: 'https://acme-v02.api.letsencrypt.org/acme/acct/1',
      def456: 'https://pebble:14000/my-account/1',
    });
  });
});
