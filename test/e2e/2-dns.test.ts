// End to end with DNS validation: a test-only driver writes the TXT records to
// challtestsrv, which Pebble asks when it validates.
import { beforeAll, describe, expect, it } from 'vitest';
import { expectServed, fileCert, prepareServer, site, zetcert } from './server';
import { HOST, ok, sh, write } from './target';

describe.sequential('DNS validation and wildcard certificates', () => {
  beforeAll(async () => {
    await prepareServer();
    await write(
      '/etc/zetcert/dns/lab.yml',
      `driver: challtestsrv\nurl: http://${HOST ? '10.231.53.3' : 'challtestsrv'}:8055\ndns: 10.231.53.3\nzones: [client.test]\n`,
    );
  });

  it('issues a wildcard certificate with deeper names through the DNS hooks', async () => {
    await site('client', 'client.test', 'wildcard.client.test');
    await site('app', 'app.client.test', 'wildcard.client.test');
    await site('api', 'api.eu.client.test', 'wildcard.client.test');
    const r = await zetcert('sync -y');
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('wildcard.client.test  new: client.test, *.client.test, *.eu.client.test (DNS via lab)');
    const file = await fileCert('wildcard.client.test');
    expect(file).toContain('DNS:client.test, DNS:*.client.test, DNS:*.eu.client.test');
    await expectServed('app.client.test', file);
    await expectServed('api.eu.client.test', file);
    // The cleanup hook removed the TXT record.
    const txt = await ok(
      `node -e "const r = new (require('dns').promises.Resolver)(); r.setServers(['10.231.53.3']); r.resolveTxt('_acme-challenge.client.test').then((x) => console.log(JSON.stringify(x)), (e) => console.log(e.code))"`,
    );
    expect(txt.trim()).toMatch(/^(ENODATA|ENOTFOUND|\[\])$/);
  });

  it('needs no new certificate for a new x.D block', async () => {
    await site('shop2', 'shop.client.test', 'wildcard.client.test');
    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('wildcard.client.test  up to date');
  });

  it('adds a deeper wildcard only while such a name is in use', async () => {
    await site('api', 'api.us.client.test', 'wildcard.client.test');
    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('wildcard.client.test  + *.us.client.test  - *.eu.client.test');
    expect(await fileCert('wildcard.client.test')).toContain('DNS:client.test, DNS:*.client.test, DNS:*.us.client.test');
  });

  it('renews DNS certificates through certbot with the hooks it saved', async () => {
    const before = await fileCert('wildcard.client.test');
    const renew = await sh('certbot renew --force-renewal --no-random-sleep-on-renew --cert-name wildcard.client.test');
    expect(renew.code).toBe(0);
    const after = await fileCert('wildcard.client.test');
    expect(after).not.toBe(before);
    await expectServed('shop.client.test', after);
  });
});
