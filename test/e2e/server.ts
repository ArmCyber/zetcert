// Prepares the server once for all e2e files: zetcert installed by `init` as a normal user, the
// config adjusted for the lab, and nginx on port 80 with zetcert's ACME location.
import { expect } from 'vitest';
import { asUser, HOST, ok, SERVER_IP, sh, write } from './target';

export const zetcert = (args: string) => sh(`zetcert ${args} --no-color`);

export async function fileCert(cert: string): Promise<string> {
  return ok(`openssl x509 -in /etc/letsencrypt/live/${cert}/cert.pem -noout -serial -ext subjectAltName`);
}

async function servedCert(name: string): Promise<string> {
  return ok(
    `echo | openssl s_client -connect 127.0.0.1:443 -servername ${name} 2>/dev/null | openssl x509 -noout -serial -ext subjectAltName`,
  );
}

/**
 * Waits until nginx serves `cert` for `name`. A reload returns before nginx has switched over: its
 * old workers can still answer the first handshakes.
 */
export async function expectServed(name: string, cert: string): Promise<void> {
  await expect.poll(() => servedCert(name), { timeout: 15_000, interval: 250 }).toBe(cert);
}

export async function site(name: string, serverNames: string, cert: string): Promise<void> {
  await write(
    `/etc/nginx/sites-enabled/${name}`,
    `server {
    listen 443 ssl;
    server_name ${serverNames};
    include /etc/nginx/zetcert/${cert}.conf;
    location / { return 200 "${name}\\n"; }
}
`,
  );
}

export async function prepareServer(): Promise<void> {
  if ((await sh('test -e /etc/zetcert/config.yml')).code === 0) return;
  // As a normal user: init runs itself again with sudo.
  const init = await asUser('zetcert init -y --no-color');
  expect(init.stdout).toContain('zetcert init needs root: running it again with sudo.');
  expect(init.code).toBe(0);
  expect(await ok('cat /usr/local/lib/zetcert/install.json')).toContain('"version"');
  await ok(`sed -i 's/^public_ips: .*/public_ips: [${SERVER_IP}]/' /etc/zetcert/config.yml`);
  if (!HOST) await ok("sed -i 's/^  reload: systemctl reload nginx/  reload: nginx -s reload/' /etc/zetcert/config.yml");
  // Port 80: zetcert's ACME location, everything else to HTTPS.
  await ok('rm -f /etc/nginx/sites-enabled/*');
  await write(
    '/etc/nginx/sites-enabled/00-port80',
    `server {
    listen 80 default_server;
    server_name _;
    include /etc/nginx/zetcert/_acme.conf;
    location / { return 301 https://$host$request_uri; }
}
`,
  );
  await ok(HOST ? 'systemctl restart nginx' : 'nginx -t && (nginx -s reload 2>/dev/null || nginx)');
}
