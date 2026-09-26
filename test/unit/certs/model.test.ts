import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { defaultConfig, parseConfig } from '../../../src/config/config';
import { buildModel, compareNames } from '../../../src/certs/model';
import { discover } from '../../../src/nginx/discovery';
import { loadNginxConfig } from '../../../src/nginx/include';
import { existingSnippets } from '../../../src/nginx/snippets';
import { tempRoot } from '../helpers';

let root: ReturnType<typeof tempRoot>;
beforeEach(() => (root = tempRoot()));
afterEach(() => root.cleanup());

/** Builds the model from nginx server blocks and an optional config. */
function model(servers: string, configYaml = '', files: Record<string, string> = {}) {
  root.write('/etc/nginx/nginx.conf', `http {\n${servers}\n}\n`);
  for (const [p, content] of Object.entries(files)) root.write(p, content);
  const config = configYaml ? parseConfig(configYaml, 'config.yml').config : defaultConfig();
  return buildModel({ config, discovery: discover(loadNginxConfig('/etc/nginx/nginx.conf')), snippets: existingSnippets() });
}
const names = (m: ReturnType<typeof model>, cert: string) => m.find((c) => c.cert === cert)?.names.map((n) => n.name);
const cert = (m: ReturnType<typeof model>, name: string) => {
  const found = m.find((c) => c.cert === name);
  if (!found) throw new Error(`no ${name}`);
  return found;
};

describe('wildcard certificates', () => {
  it('gives the names of the spec example', () => {
    const m = model(`
server { server_name client.example;         include /etc/nginx/zetcert/wildcard.client.example.conf; }
server { server_name app.client.example;     include /etc/nginx/zetcert/wildcard.client.example.conf; }
server { server_name shop.client.example;    include /etc/nginx/zetcert/wildcard.client.example.conf; }
server { server_name api.eu.client.example;  include /etc/nginx/zetcert/wildcard.client.example.conf; }`);
    expect(names(m, 'wildcard.client.example')).toEqual(['client.example', '*.client.example', '*.eu.client.example']);
    const c = cert(m, 'wildcard.client.example');
    expect(c.kind).toBe('wildcard');
    expect(c.validation).toBe('dns');
    expect(c.names[2]?.sources).toEqual([
      { type: 'nginx', raw: 'api.eu.client.example', loc: { file: '/etc/nginx/nginx.conf', line: 6 } },
    ]);
  });

  it('adds deeper wildcards only while such names are in use, and keeps *.x.D as it is', () => {
    const m = model(`
server { server_name a.b.x.client.example *.y.client.example x.client.example; include /etc/nginx/zetcert/wildcard.client.example.conf; }`);
    expect(names(m, 'wildcard.client.example')).toEqual(['client.example', '*.client.example', '*.b.x.client.example', '*.y.client.example']);
  });

  it('warns about names outside the domain and leaves them out', () => {
    const m = model(`server { server_name client.example other.example; include /etc/nginx/zetcert/wildcard.client.example.conf; }`);
    expect(names(m, 'wildcard.client.example')).toEqual(['client.example', '*.client.example']);
    expect(cert(m, 'wildcard.client.example').warnings[0]?.message).toMatch(/other.example .* is outside client.example/);
  });

  it('applies names and exclude from the config with the same rules', () => {
    const m = model(
      `server { server_name a.eu.client.example b.us.client.example; include /etc/nginx/zetcert/wildcard.client.example.conf; }`,
      `certs:\n  wildcard.client.example:\n    names: [x.asia.client.example, "*.z.client.example", mail.other.test]\n    exclude: [b.us.client.example]\n`,
    );
    expect(names(m, 'wildcard.client.example')).toEqual([
      'client.example',
      '*.client.example',
      '*.asia.client.example',
      '*.eu.client.example',
      '*.z.client.example',
    ]);
    const c = cert(m, 'wildcard.client.example');
    expect(c.dropped.map((d) => [d.name, d.reason])).toEqual([
      ['b.us.client.example', 'excluded in the config'],
      ['mail.other.test', 'outside client.example: it belongs in another certificate'],
    ]);
  });
});

describe('exclude', () => {
  it('also removes a wildcard the rules made, and warns about an entry that matches nothing', () => {
    const m = model(
      `server { server_name client.example api.eu.client.example; include /etc/nginx/zetcert/wildcard.client.example.conf; }`,
      'certs:\n  wildcard.client.example:\n    exclude: ["*.eu.client.example", gone.client.example]\n',
    );
    expect(names(m, 'wildcard.client.example')).toEqual(['client.example', '*.client.example']);
    const c = cert(m, 'wildcard.client.example');
    expect(c.dropped.map((d) => d.name)).toEqual(['*.eu.client.example']);
    expect(c.warnings.map((w) => w.message)).toEqual(["exclude: gone.client.example isn't one of wildcard.client.example's names"]);
  });
});

describe('regular certificates', () => {
  it('holds the names of the blocks that include it, plus config names, minus excluded ones', () => {
    const m = model(
      `
server { server_name store.example www.store.example; include /etc/nginx/zetcert/store.conf; }
server { server_name old.store.example shop.store.example; include /etc/nginx/zetcert/store.conf; }
server { server_name unrelated.example; }`,
      'certs:\n  store:\n    names: [extra.store.example]\n    exclude: [old.store.example]\n',
    );
    expect(names(m, 'store')).toEqual([
      'store.example',
      'extra.store.example',
      'shop.store.example',
      'www.store.example',
    ]);
    expect(cert(m, 'store').validation).toBe('http');
  });

  it('drops names covered by a wildcard and validates through DNS', () => {
    const m = model(`server { server_name foo.example *.foo.example a.foo.example a.b.foo.example; include /etc/nginx/zetcert/foo.conf; }`);
    expect(names(m, 'foo')).toEqual(['foo.example', '*.foo.example', 'a.b.foo.example']);
    expect(cert(m, 'foo').dropped).toMatchObject([{ name: 'a.foo.example', reason: 'covered by *.foo.example' }]);
    expect(cert(m, 'foo').validation).toBe('dns');
  });

  it('validates through DNS with challenge: dns', () => {
    const m = model(`server { server_name a.example; include /etc/nginx/zetcert/a.conf; }`, 'certs:\n  a:\n    challenge: dns\n');
    expect(cert(m, 'a').validation).toBe('dns');
  });

  it('reports challenge: http with a wildcard name from nginx', () => {
    const m = model(`server { server_name *.a.example; include /etc/nginx/zetcert/a.conf; }`, 'certs:\n  a:\n    challenge: http\n');
    expect(cert(m, 'a').errors[0]?.message).toMatch(/challenge: http can't validate the wildcard name \*\.a\.example \(\*\.a\.example at \/etc\/nginx\/nginx.conf:2\)/);
  });

  it('can be defined only in the config', () => {
    const m = model('', 'certs:\n  mail:\n    names: [mail.example.com]\n    deploy: ["systemctl reload postfix dovecot"]\n');
    expect(cert(m, 'mail')).toMatchObject({
      names: [{ name: 'mail.example.com', sources: [{ type: 'config' }] }],
      included: false,
      inConfig: true,
      unused: false,
      deploy: ['systemctl reload postfix dovecot'],
    });
  });

  it('merges a name found in several places', () => {
    const m = model(`
server { server_name a.example A.EXAMPLE.; include /etc/nginx/zetcert/a.conf; }
server { server_name a.example; include /etc/nginx/zetcert/a.conf; }`);
    expect(cert(m, 'a').names).toHaveLength(1);
    expect(cert(m, 'a').names[0]?.sources).toHaveLength(3);
  });
});

describe('limits', () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => `n${i}.example.com`).join(' ');

  it('refuses more than 100 names', () => {
    const m = model(`server { server_name ${many(101)}; include /etc/nginx/zetcert/big.conf; }`);
    expect(cert(m, 'big').errors[0]?.message).toMatch(/101 names: Let's Encrypt allows 100/);
  });

  it('warns above 25 names', () => {
    const m = model(`server { server_name ${many(26)}; include /etc/nginx/zetcert/big.conf; }`);
    expect(cert(m, 'big').errors).toEqual([]);
    expect(cert(m, 'big').warnings[0]?.message).toMatch(/26 names: more than 25/);
  });

  it('accepts exactly 100', () => {
    const m = model(`server { server_name ${many(100)}; include /etc/nginx/zetcert/big.conf; }`);
    expect(cert(m, 'big').errors).toEqual([]);
  });
});

describe('the managed set', () => {
  it('covers included certificates, snippet files and config entries', () => {
    const m = model(
      `server { server_name a.example; include /etc/nginx/zetcert/new.conf; }
       server { server_name b.example; include /etc/nginx/zetcert/old.conf; }`,
      'key_type: rsa\ncerts:\n  conf.only:\n    names: [c.example]\n    key_type: ecdsa\n',
      {
        '/etc/nginx/zetcert/old.conf': '',
        '/etc/nginx/zetcert/leftover.conf': '',
        '/etc/nginx/zetcert/_tls.conf': '',
        '/etc/nginx/zetcert/_ffdhe2048.pem': '',
      },
    );
    expect(m.map((c) => [c.cert, c.included, c.newInclude, c.snippetExists, c.inConfig, c.unused, c.keyType])).toEqual([
      ['conf.only', false, false, false, true, false, 'ecdsa'],
      ['leftover', false, false, true, false, true, 'rsa'],
      ['new', true, true, false, false, false, 'rsa'],
      ['old', true, false, true, false, false, 'rsa'],
    ]);
  });

  it('keeps the skipped server names of its blocks', () => {
    const m = model(`server { server_name a.example ~^x$ _; include /etc/nginx/zetcert/a.conf; }`);
    expect(cert(m, 'a').skipped.map((s) => [s.raw, s.warn])).toEqual([
      ['~^x$', true],
      ['_', false],
    ]);
  });
});

describe('compareNames', () => {
  it('sorts by domain, parents first, wildcards right after their base', () => {
    expect(['www.b.example', 'a.test', '*.b.example', 'b.example', 'api.b.example', 'x.a.test'].sort(compareNames)).toEqual([
      'b.example',
      '*.b.example',
      'api.b.example',
      'www.b.example',
      'a.test',
      'x.a.test',
    ]);
  });
});
