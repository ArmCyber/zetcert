// The config file `init` creates, with comments explaining each setting.

export interface TemplateValues {
  email?: string;
  webroot: string;
  publicIps: string[];
  notify: string;
  nginxConfig: string;
}

const quote = (s: string) => JSON.stringify(s);

export function configTemplate(v: TemplateValues): string {
  // At least one space before a comment, or YAML reads it as part of the value.
  const pad = (text: string) => `${text} `.padEnd(34);
  return `# zetcert settings. After changing them, run: sudo zetcert sync
${pad(`email: ${quote(v.email ?? '')}`)}# contact for the Let's Encrypt account; optional
${pad(`webroot: ${v.webroot}`)}# served on port 80 under /.well-known/acme-challenge/
${pad(`public_ips: [${v.publicIps.join(', ')}]`)}# for the pre-checks, added to the addresses found on this machine; needed behind NAT
${pad('key_type: ecdsa')}# ecdsa | rsa
${pad('tls:')}# overrides only; the defaults are certbot's values
  # protocols: TLSv1.3
${pad('')}# or \`tls: off\` to write no _tls.conf
nginx:
  ${`config: ${v.nginxConfig} `.padEnd(32)}# found with \`nginx -V\`
  test: nginx -t
  reload: systemctl reload nginx
precheck:
  http_address: 127.0.0.1:80
${pad('dns_propagation_timeout: 180s')}# how long the DNS hook waits for a TXT record
${pad(`notify: ${quote(v.notify)}`)}# a command that gets alerts on stdin, e.g. curl -sS --fail-with-body --max-time 30 -K /etc/zetcert/ntfy.curl --data-binary @-
${pad('certs:')}# per-certificate options, only when the defaults aren't enough
`;
}
