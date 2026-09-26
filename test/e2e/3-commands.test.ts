// End to end: doctor, notify, create/update/delete and uninstall (phase 4).
import { beforeAll, describe, expect, it } from 'vitest';
import { fileCert, prepareServer, zetcert } from './server';
import { asUser, HOST, ok, sh, write } from './target';

describe.sequential('the other commands', () => {
  beforeAll(prepareServer);

  it('doctor checks the install, certbot, nginx and the served certificates', async () => {
    const r = await zetcert('doctor');
    expect(r.stdout).toContain('✓ env -i /usr/local/sbin/zetcert --version works');
    expect(r.stdout).toContain('✓ /usr/local/lib/zetcert/zetcert.cjs and the directories above it are root-only');
    expect(r.stdout).toContain('✓ /etc/letsencrypt/renewal-hooks/deploy/zetcert is installed');
    expect(r.stdout).toMatch(/✓ nginx -t passes/);
    expect(r.stdout).toMatch(/✓ shop.test on 443 .*: shop/);
    if (!HOST) {
      // No systemd in the container, so no certbot timer.
      expect(r.stdout).toContain('✗ no active certbot timer');
      expect(r.code).toBe(1);
    }
  });

  it('notify --test runs the command with the message on stdin and the variables', async () => {
    await ok(`sed -i 's|^notify: .*|notify: "cat > /tmp/zetcert-alert; env \\| grep ^ZETCERT_ >> /tmp/zetcert-alert"|' /etc/zetcert/config.yml`);
    const r = await zetcert('notify --test');
    expect(r.code).toBe(0);
    const alert = await ok('cat /tmp/zetcert-alert');
    expect(alert).toMatch(/^\[.+\] Test alert from zetcert: notify works\./);
    expect(alert).toContain('ZETCERT_EVENT=test');
  });

  it('fixes renewal settings with a real certbot reconfigure, and re-issues to drop DNS hooks', async () => {
    await write(
      '/etc/zetcert/dns/lab.yml',
      `driver: challtestsrv\nurl: http://${HOST ? '10.231.53.3' : 'challtestsrv'}:8055\ndns: 10.231.53.3\nzones: [client.test, shop.test]\n`,
    );
    const serial = await ok("openssl x509 -in /etc/letsencrypt/live/shop/cert.pem -noout -serial");
    expect((await zetcert('update shop --challenge dns')).code).toBe(0);
    let r = await zetcert('sync -y shop');
    expect(r.stdout).toContain('renewal settings (certbot reconfigure)');
    expect(r.stdout).toContain('✓ shop: renewal settings updated');
    expect(r.code).toBe(0);
    let renewal = await ok('cat /etc/letsencrypt/renewal/shop.conf');
    expect(renewal).toContain('authenticator = manual');
    expect(renewal).toContain('manual_auth_hook = /usr/local/sbin/zetcert hook auth --cert shop');
    // reconfigure doesn't issue a new certificate.
    expect(await ok("openssl x509 -in /etc/letsencrypt/live/shop/cert.pem -noout -serial")).toBe(serial);

    expect((await zetcert('update shop --challenge auto')).code).toBe(0);
    r = await zetcert('sync -y shop');
    expect(r.stdout).toContain('manual_auth_hook /usr/local/sbin/zetcert hook auth --cert shop → (removed)');
    expect(r.code).toBe(0);
    renewal = await ok('cat /etc/letsencrypt/renewal/shop.conf');
    expect(renewal).toContain('authenticator = webroot');
    expect(renewal).not.toContain('manual_auth_hook');
  });

  it('create registers a certificate only in the config, which sync issues', async () => {
    expect((await zetcert('create mail --add mail.other.test')).code).toBe(0);
    expect(await ok('cat /etc/nginx/zetcert/mail.conf')).toContain('/var/lib/zetcert/placeholder/fullchain.pem');
    const r = await zetcert('sync -y mail');
    expect(r.code).toBe(0);
    expect(await fileCert('mail')).toContain('DNS:mail.other.test');
    expect(await ok('cat /etc/nginx/zetcert/mail.conf')).toContain('/etc/letsencrypt/live/mail/fullchain.pem');
  });

  it("update changes options; sync runs the certificate's deploy commands", async () => {
    expect((await zetcert("update mail --deploy 'touch /tmp/mail-deployed'")).code).toBe(0);
    const r = await zetcert('sync -y --force mail');
    expect(r.code).toBe(0);
    expect((await sh('test -e /tmp/mail-deployed')).code).toBe(0);
  });

  it('delete removes the certificate from certbot, its snippet and its config entry', async () => {
    const r = await zetcert('delete mail -y');
    expect(r.code).toBe(0);
    expect((await sh('test -e /etc/letsencrypt/live/mail')).code).not.toBe(0);
    expect((await sh('test -e /etc/nginx/zetcert/mail.conf')).code).not.toBe(0);
    expect(await ok('cat /etc/zetcert/config.yml')).not.toMatch(/^\s+mail:/m);
    expect((await zetcert('delete shop -y')).stderr).toContain('nginx still includes shop');
  });

  it('uninstall refuses while DNS certificates need zetcert, then removes it with --force; init reinstalls', async () => {
    const refused = await zetcert('uninstall -y');
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("renew through zetcert's hooks: wildcard.client.test");
    const r = await sh('zetcert uninstall -y --force --no-color');
    expect(r.code).toBe(0);
    expect((await sh('test -e /usr/local/sbin/zetcert')).code).not.toBe(0);
    expect(await ok('cat /etc/letsencrypt/renewal-hooks/deploy/nginx-reload')).toContain('nginx -t && ');
    expect(await ok('ls /etc/nginx/zetcert')).toContain('shop.conf');
    // The npm copy is still there: init, as a normal user, installs the system copy again.
    const init = await asUser('zetcert init -y --no-color');
    expect(init.code).toBe(0);
    expect(init.stdout).toContain('Removed /etc/letsencrypt/renewal-hooks/deploy/nginx-reload, left by an earlier uninstall.');
    expect((await sh('test -x /usr/local/sbin/zetcert')).code).toBe(0);
  });
});
