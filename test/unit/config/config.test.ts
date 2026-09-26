import { statSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { defaultConfig, loadConfig, parseConfig } from '../../../src/config/config';
import { parseDnsAccount, loadDnsAccounts } from '../../../src/config/dns-accounts';
import { ConfigEditor } from '../../../src/config/editor';
import { isValidName } from '../../../src/config/names';
import { tempRoot } from '../helpers';

const SPEC_EXAMPLE = `email: ops@example.com            # optional; contact for the LE account
webroot: /var/www/html            # served on port 80 under /.well-known/acme-challenge/
public_ips: [203.0.113.10, 203.0.113.20]   # for pre-checks; needed behind NAT
key_type: ecdsa                   # ecdsa | rsa
tls:                              # overrides only; the defaults are certbot's values
  # protocols: TLSv1.3
                                  # or \`tls: off\` to write no _tls.conf
nginx:
  config: /etc/nginx/nginx.conf   # init detects it from \`nginx -V\`
  test: nginx -t
  reload: systemctl reload nginx
precheck:
  http_address: 127.0.0.1:80
dns_propagation_timeout: 180s     # how long the DNS hook waits for a TXT record
notify: ""                        # e.g. curl -s --max-time 30 -K /etc/zetcert/ntfy.curl --data-binary @-
certs:                            # only when the defaults aren't enough
  store:
    exclude: [old.store.example]
  mail:                           # not used by nginx
    names: [mail.example.com]
    deploy: ["systemctl reload postfix dovecot"]
  wildcard.client.example:
    dns: cf-main
`;

const load = (text: string) => parseConfig(text, '/etc/zetcert/config.yml').config;
const error = (text: string) => {
  try {
    load(text);
  } catch (err) {
    return (err as Error).message;
  }
  throw new Error('expected an error');
};

describe('config', () => {
  it('loads the example from the spec', () => {
    const config = load(SPEC_EXAMPLE);
    expect(config.email).toBe('ops@example.com');
    expect(config.public_ips).toEqual(['203.0.113.10', '203.0.113.20']);
    expect(config.tls).toEqual({});
    expect(config.dns_propagation_timeout).toBe(180);
    expect(config.notify).toBe('');
    expect(config.certs.store).toEqual({ names: [], exclude: ['old.store.example'], challenge: 'auto', deploy: [] });
    expect(config.certs.mail?.deploy).toEqual(['systemctl reload postfix dovecot']);
    expect(config.certs['wildcard.client.example']?.dns).toBe('cf-main');
  });

  it('fills in every default for an empty file', () => {
    expect(load('')).toEqual(defaultConfig());
    expect(load('# only comments\n')).toEqual(defaultConfig());
    expect(defaultConfig()).toMatchObject({
      webroot: '/var/www/html',
      key_type: 'ecdsa',
      nginx: { config: '/etc/nginx/nginx.conf', test: 'nginx -t', reload: 'systemctl reload nginx' },
      precheck: { http_address: '127.0.0.1:80' },
      dns_propagation_timeout: 180,
    });
  });

  it('reads tls overrides and tls: off', () => {
    expect(load('tls: off').tls).toBe('off');
    expect(load('tls:\n  protocols: TLSv1.3\n  session_timeout: 4h\n  session_tickets: on\n  dhparam: off').tls).toEqual({
      protocols: 'TLSv1.3',
      session_timeout: '4h',
      session_tickets: 'on',
      dhparam: 'off',
    });
    expect(load('tls:\n  protocols: [TLSv1.2, TLSv1.3]\n  prefer_server_ciphers: false').tls).toEqual({
      protocols: 'TLSv1.2 TLSv1.3',
      prefer_server_ciphers: 'off',
    });
  });

  it('normalizes certificate names in names and exclude', () => {
    expect(load('certs:\n  a:\n    names: [Mail.Example.COM., bücher.example]').certs.a?.names).toEqual([
      'mail.example.com',
      'xn--bcher-kva.example',
    ]);
  });

  it('reports errors with file, line and key', () => {
    expect(error('key_type: dsa')).toBe('/etc/zetcert/config.yml:1: key_type: must be ecdsa or rsa');
    expect(error('email: x@y\nbogus: 1')).toBe(
      '/etc/zetcert/config.yml:2: bogus: unknown key (allowed: email, webroot, public_ips, key_type, tls, nginx, precheck, dns_propagation_timeout, notify, certs)',
    );
    expect(error('certs:\n  a:\n    challenge: tls')).toBe(
      '/etc/zetcert/config.yml:3: certs.a.challenge: must be auto, http or dns',
    );
    expect(error('certs:\n  Bad_Name: {}')).toMatch(/certs\.Bad_Name: invalid certificate name/);
    expect(error('public_ips: [1.2.3]')).toMatch(/public_ips\.0: not an IP address/);
    expect(error('webroot: var/www')).toMatch(/webroot: must be an absolute path/);
    expect(error('webroot: "/var/www; evil"')).toMatch(/webroot: must be an absolute path/);
    expect(error('dns_propagation_timeout: soon')).toMatch(/must be a duration/);
    expect(error('tls:\n  protocols: TLSv1.4')).toMatch(/unknown protocol TLSv1.4/);
    expect(error('tls:\n  ciphers: "A;B"')).toMatch(/tls.ciphers/);
    expect(error('certs:\n  a:\n    names: [a_b.example.com]')).toMatch(/certs.a.names.0: not a valid DNS name/);
    expect(error('email: [x')).toMatch(/^\/etc\/zetcert\/config.yml:1: /);
  });

  it('rejects challenge: http with a wildcard name', () => {
    expect(error('certs:\n  wildcard.client.example:\n    challenge: http')).toMatch(
      /challenge: a wildcard certificate is validated through DNS/,
    );
    expect(error('certs:\n  a:\n    challenge: http\n    names: ["*.a.example"]')).toMatch(/http can't validate the wildcard name \*\.a\.example/);
    expect(load('certs:\n  wildcard.client.example:\n    challenge: dns').certs['wildcard.client.example']?.challenge).toBe('dns');
  });

  it("doesn't let a wildcard certificate exclude its own names", () => {
    expect(error('certs:\n  wildcard.client.example:\n    exclude: ["*.client.example"]')).toMatch(
      /always contains client.example and \*.client.example/,
    );
  });

  it('drops a trailing slash from paths, as certbot does', () => {
    expect(load('webroot: /var/www/html/').webroot).toBe('/var/www/html');
    expect(load('webroot: /').webroot).toBe('/');
  });

  it('checks nginx times without slow backtracking', () => {
    expect(load('tls:\n  session_timeout: 1h30m').tls).toEqual({ session_timeout: '1h30m' });
    expect(load('tls:\n  session_timeout: 300').tls).toEqual({ session_timeout: '300' });
    const started = Date.now();
    expect(error(`tls:\n  session_timeout: "${'1'.repeat(40)}x"`)).toMatch(/must be an nginx time/);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('refuses a wildcard over one label', () => {
    expect(error('certs:\n  a:\n    names: ["*.com"]')).toMatch(/not a valid DNS name: \*\.com/);
  });

  it('parses durations', () => {
    expect(load('dns_propagation_timeout: 3m').dns_propagation_timeout).toBe(180);
    expect(load('dns_propagation_timeout: 90').dns_propagation_timeout).toBe(90);
  });
});

describe('names', () => {
  it('accepts [a-z0-9][a-z0-9.-]* up to 64 characters', () => {
    expect(isValidName('store')).toBe(true);
    expect(isValidName('wildcard.client.example')).toBe(true);
    expect(isValidName('0-a.b')).toBe(true);
    expect(isValidName('-a')).toBe(false);
    expect(isValidName('.a')).toBe(false);
    expect(isValidName('A')).toBe(false);
    expect(isValidName('a_b')).toBe(false);
    expect(isValidName('a/b')).toBe(false);
    expect(isValidName('a'.repeat(64))).toBe(true);
    expect(isValidName('a'.repeat(65))).toBe(false);
  });
});

describe('config files', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('uses the defaults when there is no file yet', () => {
    const loaded = loadConfig('/etc/zetcert/config.yml');
    expect(loaded.exists).toBe(false);
    expect(loaded.config).toEqual(defaultConfig());
  });

  it('keeps comments when editing and writes mode 0600', () => {
    root.write('/etc/zetcert/config.yml', SPEC_EXAMPLE);
    const editor = new ConfigEditor(loadConfig('/etc/zetcert/config.yml'));
    editor.addToList(['certs', 'store', 'exclude'], 'older.store.example');
    editor.setList(['certs', 'mail', 'deploy'], ['systemctl reload postfix']);
    editor.set(['certs', 'new.cert', 'dns'], 'aws');
    editor.removeFromList(['certs', 'mail', 'names'], 'mail.example.com');
    const saved = editor.save();
    expect(saved.config.certs.store?.exclude).toEqual(['old.store.example', 'older.store.example']);
    expect(saved.config.certs['new.cert']?.dns).toBe('aws');
    expect(saved.config.certs.mail).toEqual({ names: [], exclude: [], challenge: 'auto', deploy: ['systemctl reload postfix'] });
    const text = saved.doc.toString();
    expect(text).toContain('# optional; contact for the LE account');
    expect(text).toContain('# not used by nginx');
    expect(text).toContain('# init detects it from `nginx -V`');
    expect(statSync(root.path('/etc/zetcert/config.yml')).mode & 0o777).toBe(0o600);
  });

  it('removes a certificate entry left empty', () => {
    root.write('/etc/zetcert/config.yml', 'certs:\n  store:\n    deploy: [a]\n  mail:\n    names: [m.example.com]\n');
    const editor = new ConfigEditor(loadConfig('/etc/zetcert/config.yml'));
    editor.removeFromList(['certs', 'store', 'deploy'], 'a');
    expect(editor.save().config.certs).toEqual({
      mail: { names: ['m.example.com'], exclude: [], challenge: 'auto', deploy: [] },
    });
  });

  it('refuses edits that make the config invalid', () => {
    root.write('/etc/zetcert/config.yml', 'certs: {}\n');
    const editor = new ConfigEditor(loadConfig('/etc/zetcert/config.yml'));
    editor.set(['certs', 'a', 'challenge'], 'bogus');
    expect(() => editor.save()).toThrow(/certs.a.challenge/);
  });

  it('loads DNS accounts', () => {
    root.write('/etc/zetcert/dns/cf-main.yml', 'driver: cloudflare\ntoken: "abc"\n');
    root.write('/etc/zetcert/dns/aws.yml', 'driver: route53\n');
    root.write('/etc/zetcert/dns/notes.txt', 'ignored');
    expect(loadDnsAccounts()).toEqual([
      { name: 'aws', driver: 'route53', access_key_id: undefined, secret_access_key: undefined },
      { name: 'cf-main', driver: 'cloudflare', token: 'abc' },
    ]);
  });

  it('validates DNS account files', () => {
    expect(() => parseDnsAccount('x', 'driver: gandi')).toThrow('driver must be cloudflare or route53');
    expect(() => parseDnsAccount('x', 'driver: cloudflare')).toThrow('token is missing');
    expect(() => parseDnsAccount('x', 'driver: route53\naccess_key_id: a')).toThrow('set both');
    expect(() => parseDnsAccount('x', 'driver: cloudflare\ntoken: a\nzone: b')).toThrow('unknown key zone');
  });
});
