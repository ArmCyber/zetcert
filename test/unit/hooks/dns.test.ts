import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { setDriverFactory } from '../../../src/dns/index';
import { setPropagationDeps } from '../../../src/dns/propagation';
import { setIsRoot } from '../../../src/system/root';
import { FakeDns } from '../fake-dns';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
let dns: FakeDns;
const ENV = ['CERTBOT_IDENTIFIER', 'CERTBOT_DOMAIN', 'CERTBOT_VALIDATION', 'CERTBOT_AUTH_OUTPUT'];
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  dns = new FakeDns();
  dns.zones = { 'cf-main': ['client.example'], aws: ['eu.client.example'] };
  setDriverFactory(dns.driver);
  setPropagationDeps(dns.propagation);
  root.write('/etc/zetcert/config.yml', 'certs:\n  pinned:\n    dns: cf-main\n');
  root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: t\n');
  root.write('/etc/zetcert/dns/aws.yml', 'driver: route53\n');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  setDriverFactory(undefined);
  setPropagationDeps(undefined);
  for (const v of ENV) delete process.env[v];
});

async function hook(args: string[], env: Record<string, string>) {
  for (const v of ENV) delete process.env[v];
  Object.assign(process.env, env);
  const c = capture();
  const code = await run(['hook', ...args], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('hook auth', () => {
  it('creates the record with the matching account, prints only the reference and waits', async () => {
    const r = await hook(['auth', '--cert', 'wildcard.client.example'], { CERTBOT_IDENTIFIER: 'api.eu.client.example', CERTBOT_VALIDATION: 'v1' });
    expect(r.code).toBe(0);
    expect(dns.log).toEqual(['create aws eu.client.example _acme-challenge.api.eu.client.example v1']);
    const lines = r.out.trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] as string)).toEqual({
      account: 'aws',
      zone: { id: 'aws:eu.client.example', name: 'eu.client.example' },
      record: { name: '_acme-challenge.api.eu.client.example', value: 'v1', id: '_acme-challenge.api.eu.client.example/v1' },
    });
    expect(r.err).toContain('is visible on every authoritative nameserver of eu.client.example');
  });

  it('uses the base domain for a wildcard and falls back to CERTBOT_DOMAIN', async () => {
    const r = await hook(['auth', '--cert', 'x'], { CERTBOT_DOMAIN: 'client.example', CERTBOT_VALIDATION: 'v2' });
    expect(r.code).toBe(0);
    expect(dns.log).toEqual(['create cf-main client.example _acme-challenge.client.example v2']);
  });

  it("uses the certificate's pinned account", async () => {
    await hook(['auth', '--cert', 'pinned'], { CERTBOT_IDENTIFIER: 'api.eu.client.example', CERTBOT_VALIDATION: 'v3' });
    expect(dns.log).toEqual(['create cf-main client.example _acme-challenge.api.eu.client.example v3']);
  });

  it('works when an unrelated account is broken or its file is malformed', async () => {
    root.write('/etc/zetcert/dns/zold.yml', 'driver: cloudflare\ntoken: old\n');
    root.write('/etc/zetcert/dns/typo.yml', 'driver: route53\nacces_key_id: x\n');
    dns.broken.add('zold');
    const r = await hook(['auth', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'client.example', CERTBOT_VALIDATION: 'v' });
    expect(r.code).toBe(0);
    expect(dns.log).toEqual(['create cf-main client.example _acme-challenge.client.example v']);
    expect(r.err).toContain("warning: the zones of the DNS account zold can't be listed: Invalid access token (9109)");
    expect(r.err).toContain('warning: /etc/zetcert/dns/typo.yml: unknown key acces_key_id');
  });

  it('prints the reference before waiting, and fails when the record never shows', async () => {
    let clock = 0;
    setPropagationDeps({ ...dns.propagation, txt: async () => [], sleep: async (ms) => void (clock += ms), now: () => clock });
    const r = await hook(['auth', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'client.example', CERTBOT_VALIDATION: 'v' });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out.trim()).record.name).toBe('_acme-challenge.client.example');
    expect(r.err).toContain("isn't visible on ns1.fake after 180s (dns_propagation_timeout)");
  });

  it('explains on stderr when no account manages the name, with an empty stdout', async () => {
    const r = await hook(['auth', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'nowhere.invalid', CERTBOT_VALIDATION: 'v' });
    expect(r.code).toBe(1);
    expect(r.out).toBe('');
    expect(r.err).toContain('no DNS account manages nowhere.invalid: run zetcert dns add …');
  });
});

describe('hook cleanup', () => {
  it('deletes the record named in CERTBOT_AUTH_OUTPUT', async () => {
    const auth = await hook(['auth', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'client.example', CERTBOT_VALIDATION: 'v1' });
    const r = await hook(['cleanup', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'client.example', CERTBOT_VALIDATION: 'v1', CERTBOT_AUTH_OUTPUT: auth.out.trim() });
    expect(r.code).toBe(0);
    expect(dns.log[1]).toBe('delete cf-main client.example _acme-challenge.client.example v1');
  });

  it('without an auth output, deletes the record matching the identifier and value', async () => {
    const r = await hook(['cleanup', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'client.example', CERTBOT_VALIDATION: 'v9', CERTBOT_AUTH_OUTPUT: '' });
    expect(r.code).toBe(0);
    expect(dns.log).toEqual(['delete cf-main client.example _acme-challenge.client.example v9']);
  });

  it('only warns when the deletion fails', async () => {
    const r = await hook(['cleanup', '--cert', 'x'], { CERTBOT_IDENTIFIER: 'nowhere.invalid', CERTBOT_VALIDATION: 'v' });
    expect(r.code).toBe(0);
    expect(r.err).toContain("warning: couldn't delete the TXT record for nowhere.invalid");
  });
});
