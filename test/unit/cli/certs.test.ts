import { existsSync, readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { loadConfig } from '../../../src/config/config';
import { snippetContent } from '../../../src/nginx/snippets';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { fakeSystem } from '../fake-certbot';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  root.write('/run/.keep', '');
  root.write('/etc/zetcert/config.yml', '# settings\nemail: ops@example.com\ncerts:\n  store:  # the shop\n    exclude: [old.store.example]\n');
  root.write('/etc/nginx/nginx.conf', 'http {\n  server { server_name store.example; include /etc/nginx/zetcert/store.conf; }\n  server { server_name new.example; include /etc/nginx/zetcert/newinclude.conf; }\n}\n');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
});

async function zetcert(...args: string[]) {
  const c = capture();
  const code = await run([...args, '--no-color'], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}
const certs = () => loadConfig('/etc/zetcert/config.yml').config.certs;

describe('create', () => {
  it('registers a certificate with options and writes its placeholder snippet', async () => {
    const r = await zetcert('create', 'mail', '--add', 'mail.example.com', '--deploy', 'systemctl reload postfix dovecot', '--key-type', 'rsa');
    expect(r.code).toBe(0);
    expect(certs().mail).toEqual({ names: ['mail.example.com'], exclude: [], challenge: 'auto', key_type: 'rsa', deploy: ['systemctl reload postfix dovecot'] });
    expect(readFileSync(root.path('/etc/nginx/zetcert/mail.conf'), 'utf8')).toBe(snippetContent('mail', false));
    expect(readFileSync(root.path('/etc/zetcert/config.yml'), 'utf8')).toContain('# the shop');
  });

  it('registers a certificate without options', async () => {
    expect((await zetcert('create', 'blog')).code).toBe(0);
    expect(certs().blog).toEqual({ names: [], exclude: [], challenge: 'auto', deploy: [] });
  });

  it('refuses existing certificates and bad names', async () => {
    expect((await zetcert('create', 'store')).err).toContain('the certificate store exists: change it with zetcert update store');
    expect((await zetcert('create', 'Bad_Name')).err).toContain('invalid certificate name');
  });
});

describe('update', () => {
  it('changes options and keeps the comments', async () => {
    const r = await zetcert('update', 'store', '--add', 'Extra.Store.Example', '--unexclude', 'old.store.example', '--exclude', 'test.store.example', '--challenge', 'dns');
    expect(r.code).toBe(0);
    expect(r.err).toBe('');
    expect(certs().store).toMatchObject({ names: ['extra.store.example'], exclude: ['test.store.example'], challenge: 'dns' });
    expect(readFileSync(root.path('/etc/zetcert/config.yml'), 'utf8')).toContain('# the shop');
    expect(r.out).toContain('The next sync applies the changes');
  });

  it('adds and removes deploy commands', async () => {
    await zetcert('update', 'store', '--deploy', 'systemctl reload postfix', '--deploy', 'systemctl reload dovecot');
    expect(certs().store?.deploy).toEqual(['systemctl reload postfix', 'systemctl reload dovecot']);
    await zetcert('update', 'store', '--no-deploy');
    expect(certs().store?.deploy).toEqual([]);
    await zetcert('update', 'store', '--challenge', 'auto');
    expect(readFileSync(root.path('/etc/zetcert/config.yml'), 'utf8')).not.toContain('challenge');
  });

  it('works for a certificate nginx includes but the config does not know yet', async () => {
    expect((await zetcert('update', 'newinclude', '--key-type', 'rsa')).code).toBe(0);
    expect(certs().newinclude?.key_type).toBe('rsa');
  });

  it('refuses unknown certificates, empty updates and invalid results', async () => {
    expect((await zetcert('update', 'nope', '--key-type', 'rsa')).err).toContain('no certificate named nope: zetcert create nope registers one');
    expect((await zetcert('update', 'store')).err).toContain('nothing to change');
    await zetcert('create', 'wildcard.client.example');
    expect((await zetcert('update', 'wildcard.client.example', '--challenge', 'http')).err).toMatch(/a wildcard certificate is validated through DNS/);
    expect((await zetcert('update', 'store', '--add', 'bad_name.example')).err).toContain('not a valid DNS name: bad_name.example');
  });

  it('warns about a DNS account that does not exist yet', async () => {
    const r = await zetcert('update', 'store', '--dns', 'cf-main');
    expect(r.code).toBe(0);
    expect(r.err).toContain("there's no DNS account cf-main yet");
  });
});

describe('delete', () => {
  let sys: ReturnType<typeof fakeSystem>;
  beforeEach(() => {
    sys = fakeSystem(root);
    setExec(sys.exec);
    root.write('/etc/nginx/nginx.conf', 'http {\n  server { server_name store.example; include /etc/nginx/zetcert/store.conf; }\n}\n');
    root.write('/etc/nginx/zetcert/store.conf', snippetContent('store', true));
    root.write('/etc/nginx/zetcert/old.conf', snippetContent('old', true));
    writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'] }), 'authenticator = webroot');
    writeCertbotCert(root.write, 'old', makeCert({ names: ['old.example'] }), 'authenticator = webroot');
    root.write('/etc/zetcert/config.yml', 'certs:\n  old:\n    deploy: [x]\n  store: {}\n');
  });
  afterEach(resetExec);
  const certbot = () => sys.calls.filter((c) => c[0] === 'certbot');

  it('deletes an unused certificate: certbot, snippet and config entry', async () => {
    const r = await zetcert('delete', 'old', '-y');
    expect(r.code).toBe(0);
    expect(r.out).toContain('delete the certificate from certbot (certbot delete --cert-name old)');
    expect(certbot()).toEqual([['certbot', 'delete', '--non-interactive', '--cert-name', 'old']]);
    expect(existsSync(root.path('/etc/nginx/zetcert/old.conf'))).toBe(false);
    expect(certs().old).toBeUndefined();
  });

  it('refuses while nginx includes it', async () => {
    const r = await zetcert('delete', 'store', '-y');
    expect(r.code).toBe(1);
    expect(r.err).toContain('nginx still includes store (/etc/nginx/nginx.conf:2)');
    expect(certbot()).toEqual([]);
  });

  it('with --force, keeps the snippet on the placeholder', async () => {
    const r = await zetcert('delete', 'store', '-y', '--force');
    expect(r.code).toBe(0);
    expect(readFileSync(root.path('/etc/nginx/zetcert/store.conf'), 'utf8')).toBe(snippetContent('store', false));
    expect(existsSync(root.path('/etc/letsencrypt/live/store'))).toBe(false);
  });

  it('with --keep-cert, leaves certbot alone', async () => {
    expect((await zetcert('delete', 'old', '-y', '--keep-cert')).code).toBe(0);
    expect(certbot()).toEqual([]);
    expect(existsSync(root.path('/etc/letsencrypt/live/old'))).toBe(true);
  });

  it("refuses a certbot certificate zetcert doesn't manage", async () => {
    writeCertbotCert(root.write, 'foreign', makeCert({ names: ['foreign.example'] }), 'authenticator = standalone');
    const r = await zetcert('delete', 'foreign', '-y');
    expect(r.code).toBe(1);
    expect(r.err).toContain("zetcert doesn't manage foreign: to delete certbot's certificate, use certbot delete --cert-name foreign");
    expect(certbot()).toEqual([]);
  });

  it('keeps the config in block style after the last certificate is gone', async () => {
    root.write('/etc/zetcert/config.yml', 'certs:\n  old:\n    deploy: [x]\n');
    expect((await zetcert('delete', 'old', '-y')).code).toBe(0);
    expect((await zetcert('create', 'shop', '--add', 'shop.example.com')).code).toBe(0);
    expect(readFileSync(root.path('/etc/zetcert/config.yml'), 'utf8')).toContain('certs:\n  shop:\n    names:\n      - shop.example.com\n');
  });

  it('asks first and does nothing when declined', async () => {
    const c = capture({ confirm: false });
    expect(await run(['delete', 'old'], c.io)).toBe(1);
    expect(certbot()).toEqual([]);
    expect(existsSync(root.path('/etc/nginx/zetcert/old.conf'))).toBe(true);
  });
});
