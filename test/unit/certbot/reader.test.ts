import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseConfigObj } from '../../../src/certbot/configobj';
import {
  certbotVersion,
  parseCert,
  parseRenewal,
  readCertbotCerts,
  versionAtLeast,
} from '../../../src/certbot/reader';
import { resetExec, setExec } from '../../../src/system/exec';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { tempRoot } from '../helpers';

const WEBROOT_RENEWAL = `# renew_before_expiry = 30 days
version = 4.0.0
archive_dir = /etc/letsencrypt/archive/store
cert = /etc/letsencrypt/live/store/cert.pem

# Options used in the renewal process
[renewalparams]
account = 0123456789abcdef0123456789abcdef
authenticator = webroot
webroot_path = /var/www/html,
server = https://acme-v02.api.letsencrypt.org/directory
key_type = rsa
renew_hook = systemctl reload postfix
[[webroot_map]]
store.example = /var/www/html
www.store.example = /var/www/html
`;

describe('ConfigObj', () => {
  it('reads sections, subsections, lists, quotes and comments', () => {
    const root = parseConfigObj(`top = 1
[a]
x = hello world  # comment
list = one, two ,three
single = one,
empty = ,
quoted = "a, b # not a comment"
'key' = 'v'
[[sub]]
y = 2
[b]
z = """multi
line"""
`);
    expect(root.values).toEqual({ top: '1' });
    expect(root.sections.a?.values).toEqual({
      x: 'hello world',
      list: ['one', 'two', 'three'],
      single: ['one'],
      empty: [],
      quoted: 'a, b # not a comment',
      key: 'v',
    });
    expect(root.sections.a?.sections.sub?.values).toEqual({ y: '2' });
    expect(root.sections.b?.values).toEqual({ z: 'multi\nline' });
  });
});

describe('renewal settings', () => {
  it('reads a webroot certificate', () => {
    expect(parseRenewal(WEBROOT_RENEWAL)).toEqual({
      authenticator: 'webroot',
      installer: undefined,
      webrootPath: ['/var/www/html'],
      webrootMap: { 'store.example': '/var/www/html', 'www.store.example': '/var/www/html' },
      server: 'https://acme-v02.api.letsencrypt.org/directory',
      keyType: 'rsa',
      account: '0123456789abcdef0123456789abcdef',
      prefChalls: [],
      manualAuthHook: undefined,
      manualCleanupHook: undefined,
      deployHook: 'systemctl reload postfix',
      preHook: undefined,
      postHook: undefined,
    });
  });

  it('reads manual DNS hooks, an installer and deploy_hook', () => {
    const r = parseRenewal(`[renewalparams]
authenticator = manual
installer = nginx
pref_challs = dns-01,
manual_auth_hook = /usr/local/sbin/zetcert hook auth --cert wildcard.client.example
manual_cleanup_hook = /usr/local/sbin/zetcert hook cleanup --cert wildcard.client.example
deploy_hook = "systemctl reload postfix, dovecot"
pre_hook = systemctl stop x
post_hook = None
`);
    expect(r).toMatchObject({
      authenticator: 'manual',
      installer: 'nginx',
      prefChalls: ['dns-01'],
      manualAuthHook: '/usr/local/sbin/zetcert hook auth --cert wildcard.client.example',
      manualCleanupHook: '/usr/local/sbin/zetcert hook cleanup --cert wildcard.client.example',
      deployHook: 'systemctl reload postfix, dovecot',
      preHook: 'systemctl stop x',
      postHook: undefined,
    });
  });
});

describe('certificates', () => {
  it('reads names, validity, issuer and key type', () => {
    const notBefore = new Date('2026-09-01T00:00:00Z');
    const notAfter = new Date('2026-11-30T00:00:00Z');
    const c = parseCert(makeCert({ names: ['a.example', '*.a.example'], notBefore, notAfter, issuer: 'R11', keyType: 'rsa' }).pem);
    expect(c).toMatchObject({ names: ['a.example', '*.a.example'], notBefore, notAfter, issuer: 'CN=R11', keyType: 'rsa' });
    expect(parseCert(makeCert({ names: ['b.example'] }).pem).keyType).toBe('ecdsa');
  });
});

describe('reading certbot', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => {
    root.cleanup();
    resetExec();
  });

  it('lists lineages with their certificate, settings and staging state', () => {
    writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'], issuer: 'E7' }), 'authenticator = webroot\nserver = https://acme-v02.api.letsencrypt.org/directory');
    writeCertbotCert(root.write, 'test', makeCert({ names: ['t.example'], issuer: '(STAGING) Ersatz Edamame E1' }), 'authenticator = webroot');
    writeCertbotCert(root.write, 'staged', makeCert({ names: ['s.example'] }), 'server = https://acme-staging-v02.api.letsencrypt.org/directory');
    root.write('/etc/letsencrypt/renewal/broken.conf', '[renewalparams]\nauthenticator = webroot\n');
    const certs = readCertbotCerts();
    expect(certs.map((c) => [c.name, c.cert?.names ?? null, c.staging])).toEqual([
      ['broken', null, false],
      ['staged', ['s.example'], true],
      ['store', ['store.example'], false],
      ['test', ['t.example'], true],
    ]);
  });

  it('reads the certbot version from stdout or stderr', async () => {
    setExec(async () => ({ code: 0, stdout: 'certbot 4.0.0\n', stderr: '', timedOut: false }));
    expect(await certbotVersion()).toEqual({ major: 4, minor: 0, patch: 0, text: '4.0.0' });
    setExec(async () => ({ code: 0, stdout: '', stderr: 'certbot 1.21.0\n', timedOut: false }));
    const old = await certbotVersion();
    expect(old && versionAtLeast(old, 2, 3)).toBe(false);
    setExec(async () => {
      throw Object.assign(new Error('spawn certbot ENOENT'), { code: 'ENOENT' });
    });
    expect(await certbotVersion()).toBeUndefined();
  });
});
