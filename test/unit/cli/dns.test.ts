import { readFileSync, statSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { setDriverFactory } from '../../../src/dns/index';
import { setPropagationDeps } from '../../../src/dns/propagation';
import { setIsRoot } from '../../../src/system/root';
import { loadState } from '../../../src/system/state';
import { FakeDns } from '../fake-dns';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
let dns: FakeDns;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  dns = new FakeDns();
  dns.zones = { 'cf-main': ['client.example', 'example.org'], aws: ['other.invalid'] };
  setDriverFactory(dns.driver);
  setPropagationDeps(dns.propagation);
  root.write('/etc/zetcert/config.yml', '');
  root.write('/etc/nginx/nginx.conf', 'http {\n  server { server_name client.example *.client.example; include /etc/nginx/zetcert/wildcard.client.example.conf; }\n}\n');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  setDriverFactory(undefined);
  setPropagationDeps(undefined);
});

async function zetcert(args: string[], answers: Parameters<typeof capture>[0] = {}) {
  const c = capture(answers);
  const code = await run([...args, '--no-color'], c.io);
  return { code, out: c.stdout(), err: c.stderr(), questions: c.questions };
}

describe('dns add', () => {
  it('asks for a Cloudflare token without showing it, checks it and saves the account (0600)', async () => {
    const r = await zetcert(['dns', 'add', 'cf-main', '--driver', 'cloudflare'], { secret: { 'Cloudflare API token:': 'tok-123' } });
    expect(r.code).toBe(0);
    expect(r.questions).toEqual(['Cloudflare API token:']);
    expect(r.out).toContain('Zones: client.example, example.org');
    expect(readFileSync(root.path('/etc/zetcert/dns/cf-main.yml'), 'utf8')).toBe('driver: cloudflare\ntoken: tok-123\n');
    expect(statSync(root.path('/etc/zetcert/dns/cf-main.yml')).mode & 0o777).toBe(0o600);
    expect(loadState().zones['cf-main']?.zones.map((z) => z.name)).toEqual(['client.example', 'example.org']);
  });

  it('reads Route 53 keys from stdin, or none for the AWS default chain', async () => {
    expect((await zetcert(['dns', 'add', 'aws', '--driver', 'route53', '--from-stdin'], { stdin: 'AKID\nsecret\n' })).code).toBe(0);
    expect(readFileSync(root.path('/etc/zetcert/dns/aws.yml'), 'utf8')).toBe('driver: route53\naccess_key_id: AKID\nsecret_access_key: secret\n');
    dns.zones.chain = ['x.test'];
    expect((await zetcert(['dns', 'add', 'chain', '--driver', 'route53', '--from-stdin'], { stdin: '\n' })).code).toBe(0);
    expect(readFileSync(root.path('/etc/zetcert/dns/chain.yml'), 'utf8')).toBe('driver: route53\n');
  });

  it('needs a terminal or --from-stdin for the credentials', async () => {
    const r = await zetcert(['dns', 'add', 'aws', '--driver', 'route53'], { interactive: false });
    expect(r.code).toBe(1);
    expect(r.err).toContain('no terminal to ask for the credentials: pass them on stdin with --from-stdin');
    expect(() => statSync(root.path('/etc/zetcert/dns/aws.yml'))).toThrow();
  });

  it("doesn't save credentials that don't work", async () => {
    dns.broken.add('bad');
    const r = await zetcert(['dns', 'add', 'bad', '--driver', 'cloudflare', '--from-stdin'], { stdin: 'nope' });
    expect(r.code).toBe(1);
    expect(r.err).toContain("the credentials don't work: Invalid access token (9109)");
    expect(() => statSync(root.path('/etc/zetcert/dns/bad.yml'))).toThrow();
  });

  it('refuses bad names, drivers and existing accounts', async () => {
    expect((await zetcert(['dns', 'add', 'Bad_Name', '--driver', 'cloudflare'])).err).toContain('invalid DNS account name');
    expect((await zetcert(['dns', 'add', 'x', '--driver', 'gandi'])).err).toContain('--driver must be cloudflare or route53');
    await zetcert(['dns', 'add', 'cf-main', '--driver', 'cloudflare', '--from-stdin'], { stdin: 't' });
    expect((await zetcert(['dns', 'add', 'cf-main', '--driver', 'cloudflare', '--from-stdin'], { stdin: 't' })).err).toContain('exists');
  });
});

describe('dns list, test and remove', () => {
  beforeEach(async () => {
    await zetcert(['dns', 'add', 'cf-main', '--driver', 'cloudflare', '--from-stdin'], { stdin: 't' });
    await zetcert(['dns', 'add', 'aws', '--driver', 'route53', '--from-stdin'], { stdin: '\n' });
  });

  it('lists accounts with their zones, as text or JSON', async () => {
    const r = await zetcert(['dns', 'list']);
    expect(r.out).toBe('ACCOUNT  DRIVER      ZONES\naws      route53     other.invalid\ncf-main  cloudflare  client.example, example.org\n');
    const json = JSON.parse((await zetcert(['dns', 'list', '--json'])).out);
    expect(json.accounts[1]).toEqual({ name: 'cf-main', driver: 'cloudflare', zones: ['client.example', 'example.org'], error: null });
  });

  it('creates and deletes a test record in the zone of a name', async () => {
    const r = await zetcert(['dns', 'test', 'cf-main', 'app.client.example']);
    expect(r.code).toBe(0);
    expect(dns.log.map((l) => l.split(' ').slice(0, 4).join(' '))).toEqual([
      'create cf-main client.example _acme-challenge.app.client.example',
      'delete cf-main client.example _acme-challenge.app.client.example',
    ]);
    expect(r.out).toContain('The record is visible on every authoritative nameserver.');
    expect((await zetcert(['dns', 'test', 'cf-main', 'nowhere.invalid'])).err).toContain('cf-main has no zone for nowhere.invalid');
  });

  it('refuses to remove an account a certificate uses', async () => {
    const r = await zetcert(['dns', 'remove', 'cf-main']);
    expect(r.code).toBe(1);
    expect(r.err).toContain('cf-main is used by wildcard.client.example');
    root.write('/etc/zetcert/config.yml', 'certs:\n  mail:\n    names: [mail.other.invalid]\n    dns: aws\n');
    expect((await zetcert(['dns', 'remove', 'aws'])).err).toContain('aws is used by mail');
  });

  it("refuses to remove an account while another account's zones can't be listed", async () => {
    root.write('/etc/zetcert/dns/zold.yml', 'driver: cloudflare\ntoken: old\n');
    dns.broken.add('zold');
    const r = await zetcert(['dns', 'remove', 'aws']);
    expect(r.code).toBe(1);
    expect(r.err).toContain("can't check which certificates use aws: the zones of zold can't be listed: Invalid access token (9109)");
    expect(statSync(root.path('/etc/zetcert/dns/aws.yml')).isFile()).toBe(true);
  });

  it('lists and removes an account file that can no longer be read', async () => {
    root.write('/etc/zetcert/dns/typo.yml', 'driver: route53\nacces_key_id: x\n');
    const list = await zetcert(['dns', 'list']);
    expect(list.out).toContain('typo     ?');
    expect(list.err).toContain('typo: /etc/zetcert/dns/typo.yml: unknown key acces_key_id');
    expect((await zetcert(['dns', 'remove', 'typo'])).code).toBe(0);
    expect(() => statSync(root.path('/etc/zetcert/dns/typo.yml'))).toThrow();
  });

  it('removes an account nothing uses', async () => {
    const r = await zetcert(['dns', 'remove', 'aws']);
    expect(r.code).toBe(0);
    expect(() => statSync(root.path('/etc/zetcert/dns/aws.yml'))).toThrow();
    expect(loadState().zones.aws).toBeUndefined();
  });
});
