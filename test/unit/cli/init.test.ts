import { chmodSync, existsSync, lstatSync, readFileSync, readlinkSync, statSync, writeFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { nginxConfPath } from '../../../src/cli/init';
import { run } from '../../../src/cli/program';
import { loadConfig } from '../../../src/config/config';
import { resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { VERSION } from '../../../src/version';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { capture, tempRoot } from '../helpers';

const NPM_BUNDLE = '/usr/local/lib/node_modules/zetcert/dist/zetcert.cjs';
const NODE = '/usr/bin/node';
const NGINX_V =
  "nginx version: nginx/1.26.3\nbuilt with OpenSSL 3.5.0\nTLS SNI support enabled\nconfigure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log\n";

let root: ReturnType<typeof tempRoot>;
let calls: string[][];
let tools: { certbot: boolean; nginxTestFails: boolean };

beforeEach(() => {
  root = tempRoot();
  calls = [];
  tools = { certbot: true, nginxTestFails: false };
  setIsRoot(true);
  root.write(NPM_BUNDLE, '// the bundle\n');
  root.write('/usr/local/lib/node_modules/zetcert/package.json', `{"name": "zetcert", "version": "${VERSION}"}`);
  root.write(NODE, 'node binary');
  root.write('/etc/nginx/nginx.conf', 'http { }\n');
  root.write('/run/.keep', '');
  setExec(async (command, args) => {
    calls.push([command, ...args]);
    const ok = (stdout = '', stderr = '') => ({ code: 0, stdout, stderr, timedOut: false });
    if (command === 'certbot') {
      if (!tools.certbot) throw Object.assign(new Error('spawn certbot ENOENT'), { code: 'ENOENT' });
      return ok('certbot 4.0.0\n');
    }
    if (command === 'nginx') return ok('', NGINX_V);
    if (command === 'openssl' && args[0] === 'version') return ok('OpenSSL 3.5.7 9 Jun 2026\n');
    if (command === 'openssl' && args[0] === 'req') {
      const cert = makeCert({ names: ['zetcert placeholder'] });
      writeFileSync(args[args.indexOf('-keyout') + 1] as string, cert.key);
      writeFileSync(args[args.indexOf('-out') + 1] as string, cert.pem);
      return ok();
    }
    if (command === 'sh' && args[1] === 'nginx -t') return tools.nginxTestFails ? { code: 1, stdout: '', stderr: 'nginx: [emerg] bad', timedOut: false } : ok();
    return ok();
  });
});
afterEach(() => {
  root.cleanup();
  setIsRoot(undefined);
  resetExec();
});

/** Makes the test tree look root-owned (the test user plays root) and not writable by others. */
function rootOwnedModes() {
  for (const p of ['/', '/usr', '/usr/bin', '/usr/bin/node', '/usr/local', '/usr/local/lib']) chmodSync(root.path(p), 0o755);
}

async function init(options: { argv?: string[]; rootUid?: number; answers?: Record<string, string>; bundle?: string } = {}) {
  const c = capture({ ask: options.answers });
  const argv = options.argv ?? ['init', '-y'];
  const code = await run(argv, {
    ...c.io,
    initEnv: { bundle: options.bundle ?? NPM_BUNDLE, node: NODE, argv, rootUid: options.rootUid ?? process.getuid?.() },
  });
  return { code, out: c.stdout(), err: c.stderr(), questions: c.questions };
}

describe('init', () => {
  it('runs itself again with sudo when not root', async () => {
    setIsRoot(false);
    const r = await init({ argv: ['init'] });
    expect(r.code).toBe(0);
    expect(calls).toEqual([['sudo', NODE, NPM_BUNDLE, 'init']]);
  });

  it('installs the system copy, the config, the support files, the placeholder and the hooks', async () => {
    rootOwnedModes();
    const r = await init();
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    expect(readFileSync(root.path('/usr/local/lib/zetcert/zetcert.cjs'), 'utf8')).toBe('// the bundle\n');
    expect(readlinkSync(root.path('/usr/local/lib/zetcert/node'))).toBe(NODE);
    expect(JSON.parse(readFileSync(root.path('/usr/local/lib/zetcert/install.json'), 'utf8'))).toEqual({ version: VERSION, npm: NPM_BUNDLE });
    const launcher = readFileSync(root.path('/usr/local/sbin/zetcert'), 'utf8');
    expect(launcher).toContain('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin');
    expect(launcher).toContain('exec /usr/local/lib/zetcert/node /usr/local/lib/zetcert/zetcert.cjs "$@"');
    expect(statSync(root.path('/usr/local/sbin/zetcert')).mode & 0o777).toBe(0o755);

    const config = loadConfig('/etc/zetcert/config.yml');
    expect(config.exists).toBe(true);
    expect(config.config.nginx.config).toBe('/etc/nginx/nginx.conf');
    expect(statSync(root.path('/etc/zetcert/config.yml')).mode & 0o777).toBe(0o600);

    for (const f of ['_tls.conf', '_ffdhe2048.pem', '_acme.conf']) {
      expect(statSync(root.path(`/etc/nginx/zetcert/${f}`)).mode & 0o777).toBe(0o644);
    }
    expect(statSync(root.path('/var/lib/zetcert/placeholder/privkey.pem')).mode & 0o777).toBe(0o600);
    expect(readFileSync(root.path('/etc/letsencrypt/renewal-hooks/deploy/zetcert'), 'utf8')).toContain('exec /usr/local/sbin/zetcert hook deploy');
    expect(readFileSync(root.path('/etc/letsencrypt/renewal-hooks/post/zetcert'), 'utf8')).toContain('exec /usr/local/sbin/zetcert hook post');
    expect(r.out).toContain('Next:');
    expect(calls.some((c) => c[0] === 'sh')).toBe(false);
  });

  it('copies Node when it is not owned and writable only by root', async () => {
    const r = await init({ rootUid: 12345 });
    expect(r.out).toContain(`Node: copied ${NODE} into /usr/local/lib/zetcert/node`);
    expect(lstatSync(root.path('/usr/local/lib/zetcert/node')).isSymbolicLink()).toBe(false);
    expect(readFileSync(root.path('/usr/local/lib/zetcert/node'), 'utf8')).toBe('node binary');
  });

  it('copies Node from a snap, whose path changes on refresh', async () => {
    rootOwnedModes();
    root.write('/snap/node/123/bin/node', 'snap node');
    const c = capture();
    const argv = ['init', '-y'];
    const code = await run(argv, { ...c.io, initEnv: { bundle: NPM_BUNDLE, node: '/snap/node/123/bin/node', argv, rootUid: process.getuid?.() } });
    expect(code).toBe(0);
    expect(c.stdout()).toContain("because a snap's path changes when it updates");
    expect(lstatSync(root.path('/usr/local/lib/zetcert/node')).isSymbolicLink()).toBe(false);
  });

  it('removes the plain hook an earlier uninstall left', async () => {
    root.write('/etc/letsencrypt/renewal-hooks/deploy/nginx-reload', '#!/bin/sh\n# Left by zetcert uninstall: reloads nginx after certbot renews a certificate.\nnginx -t && systemctl reload nginx\n');
    root.write('/etc/letsencrypt/renewal-hooks/deploy/mine', '#!/bin/sh\necho my own hook\n');
    const r = await init();
    expect(r.out).toContain('Removed /etc/letsencrypt/renewal-hooks/deploy/nginx-reload, left by an earlier uninstall.');
    expect(existsSync(root.path('/etc/letsencrypt/renewal-hooks/deploy/nginx-reload'))).toBe(false);
    expect(existsSync(root.path('/etc/letsencrypt/renewal-hooks/deploy/mine'))).toBe(true);
  });

  it('is safe to run again and keeps the config', async () => {
    await init();
    root.write('/etc/zetcert/config.yml', 'email: kept@example.com\n');
    calls = [];
    const r = await init();
    expect(r.code).toBe(0);
    expect(loadConfig('/etc/zetcert/config.yml').config.email).toBe('kept@example.com');
    expect(r.out).not.toContain('Next:');
    expect(r.out).not.toContain('Wrote');
    expect(calls.filter((c) => c[0] === 'openssl' && c[1] === 'req')).toEqual([]);
  });

  it('reloads nginx after nginx -t when a file nginx uses changed, e.g. after an upgrade', async () => {
    await init();
    root.write('/etc/nginx/zetcert/_tls.conf', '# older defaults\n');
    calls = [];
    const r = await init();
    expect(calls.filter((c) => c[0] === 'sh')).toEqual([
      ['sh', '-c', 'nginx -t'],
      ['sh', '-c', 'systemctl reload nginx'],
    ]);
    expect(r.out).toContain('Reloaded nginx.');
  });

  it('restores the previous files when nginx -t fails', async () => {
    await init();
    root.write('/etc/nginx/zetcert/_tls.conf', '# older defaults\n');
    tools.nginxTestFails = true;
    const r = await init();
    expect(r.code).toBe(1);
    expect(r.err).toContain('nginx -t failed with the new files');
    expect(readFileSync(root.path('/etc/nginx/zetcert/_tls.conf'), 'utf8')).toBe('# older defaults\n');
  });

  it('upgrades from a newer npm copy and runs the new copy', async () => {
    await init();
    root.write('/usr/local/lib/node_modules/zetcert/package.json', '{"name": "zetcert", "version": "99.0.0"}');
    root.write(NPM_BUNDLE, '// the new bundle\n');
    calls = [];
    const r = await init({ bundle: '/usr/local/lib/zetcert/zetcert.cjs' });
    expect(r.out).toContain(`Upgrading the system copy from ${VERSION} to 99.0.0`);
    expect(readFileSync(root.path('/usr/local/lib/zetcert/zetcert.cjs'), 'utf8')).toBe('// the new bundle\n');
    expect(calls).toEqual([[root.path('/usr/local/lib/zetcert/node'), root.path('/usr/local/lib/zetcert/zetcert.cjs'), 'init', '-y']]);
  });

  it('stops when certbot is missing', async () => {
    tools.certbot = false;
    const r = await init();
    expect(r.code).toBe(1);
    expect(r.err).toContain('zetcert needs certbot (apt install certbot, or the snap)');
  });

  it('asks for the config values', async () => {
    const r = await init({
      argv: ['init'],
      answers: {
        "Email for the Let's Encrypt account (optional):": 'ops@example.com',
        "This server's public IP addresses, separated by commas (for the pre-checks):": '203.0.113.10, 203.0.113.20',
        'Command that gets alerts on stdin (optional):': 'curl -s -K /etc/zetcert/ntfy.curl --data-binary @-',
      },
    });
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    const config = loadConfig('/etc/zetcert/config.yml').config;
    expect(config.email).toBe('ops@example.com');
    expect(config.public_ips).toEqual(['203.0.113.10', '203.0.113.20']);
    expect(config.webroot).toBe('/var/www/html');
    expect(config.notify).toBe('curl -s -K /etc/zetcert/ntfy.curl --data-binary @-');
    expect(r.questions).toHaveLength(4);
  });
});

describe('init with certificates certbot already has', () => {
  it('offers to import them', async () => {
    root.write('/run/.keep', '');
    writeCertbotCert(root.write, 'store', makeCert({ names: ['store.example'] }), 'authenticator = webroot\nrenew_hook = systemctl reload postfix');
    const r = await init();
    expect(r.code).toBe(0);
    expect(r.questions).toContain("certbot has certificates zetcert doesn't manage yet: store. Import them?");
    expect(readFileSync(root.path('/etc/nginx/zetcert/store.conf'), 'utf8')).toContain('/etc/letsencrypt/live/store/fullchain.pem');
    expect(loadConfig('/etc/zetcert/config.yml').config.certs.store?.deploy).toEqual(['systemctl reload postfix']);
  });
});

describe('nginxConfPath', () => {
  it('reads --conf-path, else <prefix>/conf/nginx.conf', () => {
    expect(nginxConfPath(NGINX_V)).toBe('/etc/nginx/nginx.conf');
    expect(nginxConfPath('configure arguments: --prefix=/opt/nginx')).toBe('/opt/nginx/conf/nginx.conf');
    expect(nginxConfPath('configure arguments:')).toBe('/usr/local/nginx/conf/nginx.conf');
  });
});
