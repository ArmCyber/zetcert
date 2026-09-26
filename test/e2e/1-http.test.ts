// End to end with HTTP validation: Pebble plays Let's Encrypt, challtestsrv the DNS.
import { beforeAll, describe, expect, it } from 'vitest';
import { expectServed, fileCert, prepareServer, site, zetcert } from './server';
import { ok, SERVER_IP, setA, sh } from './target';

describe.sequential('HTTP validation', () => {
  beforeAll(prepareServer);

  it('issues a first certificate and reloads nginx', async () => {
    await site('shop', 'shop.test www.shop.test', 'shop');
    const r = await zetcert('sync -y');
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('shop  new: shop.test, www.shop.test');
    const file = await fileCert('shop');
    expect(file).toContain('DNS:shop.test, DNS:www.shop.test');
    await expectServed('shop.test', file);
    expect(await ok('cat /etc/nginx/zetcert/shop.conf')).toContain('/etc/letsencrypt/live/shop/fullchain.pem');
  });

  it('makes no certbot call when nothing changed', async () => {
    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('shop  up to date');
    expect(r.stdout).toContain('Nothing to do.');
  });

  it('adds and removes names', async () => {
    await site('shop', 'shop.test api.shop.test', 'shop');
    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('shop  + api.shop.test  - www.shop.test');
    const file = await fileCert('shop');
    expect(file).toContain('DNS:shop.test, DNS:api.shop.test');
    await expectServed('api.shop.test', file);
  });

  it('takes a new include from the placeholder to an issued certificate', async () => {
    await site('blog', 'blog.test', 'blog');
    const dry = await zetcert('sync -y --dry-run');
    expect(dry.code).toBe(0);
    expect(dry.stdout).toContain('Created /etc/nginx/zetcert/blog.conf (placeholder until it is issued).');
    expect(dry.stdout).toContain('✓ blog: test issuance passed (--dry-run)');
    expect((await sh('test -e /etc/letsencrypt/live/blog')).code).not.toBe(0);
    const status = await zetcert('status --check blog');
    expect(status.code).toBe(2);
    expect(status.stdout).toContain('nginx uses the placeholder certificate');

    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
    await expectServed('blog.test', await fileCert('blog'));
  });

  it('skips a name that fails the pre-checks', async () => {
    await setA('broken.shop.test', '10.231.53.99');
    await site('shop', 'shop.test api.shop.test broken.shop.test', 'shop');
    const before = await fileCert('shop');
    const r = await zetcert('sync -y');
    expect(r.code).toBe(2);
    expect(r.stdout).toContain(`skipped broken.shop.test: points to 10.231.53.99, which isn't this server (${SERVER_IP})`);
    expect(await fileCert('shop')).toBe(before);
    expect((await zetcert('status --check shop')).stdout).toContain('skipped by the last sync: broken.shop.test');
  });

  it("skips a name Let's Encrypt rejects", async () => {
    const r = await zetcert('sync -y --no-precheck');
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("shop: Let's Encrypt rejected broken.shop.test");
    expect(r.stderr).toContain('skipped shop: broken.shop.test');
  });

  it('forgets skipped names once they are gone from nginx', async () => {
    await site('shop', 'shop.test api.shop.test', 'shop');
    const r = await zetcert('sync -y');
    expect(r.code).toBe(0);
  });

  it('lets certbot renew call the hooks, which reload nginx', async () => {
    const before = await fileCert('shop');
    const renew = await sh('certbot renew --force-renewal --no-random-sleep-on-renew --cert-name shop');
    expect(renew.code).toBe(0);
    const after = await fileCert('shop');
    expect(after).not.toBe(before);
    await expectServed('shop.test', after);
  });

  it('is healthy in status --check', async () => {
    const r = await zetcert('status --check');
    expect(r.stdout).toMatch(/shop +regular +http +2 .* ok/);
    expect(r.code).toBe(0);
  });
});
