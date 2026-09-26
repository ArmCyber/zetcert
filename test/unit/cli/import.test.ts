import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { loadConfig } from '../../../src/config/config';
import { snippetContent } from '../../../src/nginx/snippets';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { capture, tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
beforeEach(() => {
  root = tempRoot();
  setIsRoot(true);
  setExec(async () => ({ code: 0, stdout: 'certbot 4.0.0\n', stderr: '', timedOut: false }));
  root.write('/run/.keep', '');
  root.write('/etc/zetcert/config.yml', '# my settings\nemail: ops@example.com\n');
  root.write(
    '/etc/nginx/nginx.conf',
    'http {\n  server { listen 443 ssl; server_name store.example shop.store.example; include /etc/nginx/includes/ssl.conf; }\n}\n',
  );
  root.write('/etc/nginx/includes/ssl.conf', 'include /etc/nginx/zetcert/store.conf;\n');
  writeCertbotCert(
    root.write,
    'store',
    makeCert({ names: ['store.example', 'www.store.example'], keyType: 'rsa' }),
    'authenticator = nginx\ninstaller = nginx\nrenew_hook = systemctl reload postfix\npost_hook = echo done',
  );
  writeCertbotCert(root.write, 'mail', makeCert({ names: ['mail.example.com'] }), 'authenticator = standalone');
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  resetExec();
});

async function zetcert(...args: string[]) {
  const c = capture();
  const code = await run([...args, '--no-color'], c.io);
  return { code, out: c.stdout(), err: c.stderr() };
}

describe('import', () => {
  it("writes the snippet, moves the deploy hook and shows how nginx's names differ", async () => {
    const r = await zetcert('import', 'store');
    expect(r.code).toBe(0);
    expect(readFileSync(root.path('/etc/nginx/zetcert/store.conf'), 'utf8')).toBe(snippetContent('store', true));
    const config = loadConfig('/etc/zetcert/config.yml');
    expect(config.config.certs.store?.deploy).toEqual(['systemctl reload postfix']);
    expect(config.doc.toString()).toContain('# my settings');
    expect(r.out).toContain("store: moved certbot's deploy hook into its deploy list: systemctl reload postfix");
    expect(r.err).toContain(`certbot's post hook "echo done" isn't used by zetcert`);
    expect(r.out).toContain('the certificate has: store.example, www.store.example');
    expect(r.out).toContain('the next sync changes it: + shop.store.example  - www.store.example');
  });

  it('says when nginx does not use the certificate yet', async () => {
    const r = await zetcert('import', 'mail');
    expect(r.out).toContain("nginx doesn't use it yet: add include /etc/nginx/zetcert/mail.conf; to its server blocks.");
  });

  it('imports every certificate with --all, and is safe to repeat', async () => {
    expect((await zetcert('import', '--all')).code).toBe(0);
    const again = await zetcert('import', '--all');
    expect(again.code).toBe(0);
    expect(loadConfig('/etc/zetcert/config.yml').config.certs.store?.deploy).toEqual(['systemctl reload postfix']);
  });

  it('reports certificates certbot does not have', async () => {
    const r = await zetcert('import', 'nope');
    expect(r.code).toBe(1);
    expect(r.err).toContain('certbot has no certificate named nope');
    expect((await zetcert('import')).err).toContain('name the certificates to import, or use --all');
  });
});
