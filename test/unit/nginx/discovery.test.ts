import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readServerName } from '../../../src/certs/names';
import { discover } from '../../../src/nginx/discovery';
import { loadNginxConfig } from '../../../src/nginx/include';
import { resetRoot, setRoot } from '../../../src/system/paths';
import { tempRoot } from '../helpers';

describe('server_name rules', () => {
  const used = (raw: string) => readServerName(raw);
  it.each([
    ['example.com', ['example.com']],
    ['www.example.com', ['www.example.com']],
    ['WWW.Example.COM.', ['www.example.com']],
    ['bücher.example', ['xn--bcher-kva.example']],
    ['*.example.com', ['*.example.com']],
    ['.example.com', ['example.com', '*.example.com']],
  ])('uses %s', (raw, names) => expect(used(raw)).toEqual({ names }));

  it.each([
    ['~^www\\.(.+)$', true],
    ['www.example.*', true],
    ['_', false],
    ['', false],
    ['localhost', false],
    ['127.0.0.1', false],
    ['[::1]', false],
    ['myhost', false],
    ['$hostname', false],
    ['example.com:8080', true],
    ['a_b.example.com', true],
  ])('skips %j (warning: %s)', (raw, warn) => {
    const result = used(raw);
    expect(result).toMatchObject({ warn });
    expect('skip' in result).toBe(true);
  });
});

describe('discovery', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  const run = (nginxConf: string, files: Record<string, string> = {}) => {
    root.write('/etc/nginx/nginx.conf', nginxConf);
    for (const [p, content] of Object.entries(files)) root.write(p, content);
    return discover(loadNginxConfig('/etc/nginx/nginx.conf'));
  };

  it('finds snippet includes directly and through nested includes', () => {
    const d = run(
      `http {
  server {
    listen 443 ssl;
    server_name a.example.com b.example.com;
    include /etc/nginx/zetcert/one.conf;
  }
  server {
    listen 443 ssl;
    server_name c.example.com;
    include includes/ssl.conf;
  }
}`,
      {
        '/etc/nginx/zetcert/one.conf': 'ssl_certificate x;',
        '/etc/nginx/includes/ssl.conf': 'include inner.conf;',
        '/etc/nginx/inner.conf': 'include /etc/nginx/zetcert/two.conf;',
      },
    );
    expect(d.servers.map((s) => [s.cert, s.names.map((n) => n.name)])).toEqual([
      ['one', ['a.example.com', 'b.example.com']],
      ['two', ['c.example.com']],
    ]);
    expect(d.snippetIncludes).toEqual([
      { cert: 'one', exists: true, file: '/etc/nginx/nginx.conf', line: 5 },
      { cert: 'two', exists: false, file: '/etc/nginx/inner.conf', line: 1 },
    ]);
    expect(d.servers[0]?.ownCertificate).toBe(false);
    expect(d.errors).toEqual([]);
    expect(d.missing).toEqual([]);
  });

  it('applies http {} inheritance to listen … ssl/quic blocks without a certificate', () => {
    const d = run(`http {
  include /etc/nginx/zetcert/main.conf;
  server { listen 443 ssl; server_name a.example.com; }
  server { listen 443 quic; server_name q.example.com; }
  server { listen 80; server_name plain.example.com; }
  server { listen 443 ssl; server_name own.example.com; ssl_certificate /x.pem; }
  server { listen 443 ssl; server_name other.example.com; include /etc/nginx/zetcert/other.conf; }
}`);
    expect(d.httpSnippet?.cert).toBe('main');
    expect(d.servers.map((s) => [s.names[0]?.name, s.cert ?? null, s.inherited])).toEqual([
      ['a.example.com', 'main', true],
      ['q.example.com', 'main', true],
      ['plain.example.com', null, false],
      ['own.example.com', null, false],
      ['other.example.com', 'other', false],
    ]);
  });

  it('reports two snippets in one server block as an error with file:line', () => {
    const d = run(
      `http {
  server {
    server_name a.example.com;
    include /etc/nginx/zetcert/one.conf;
    include /etc/nginx/includes/ssl.conf;
  }
}`,
      { '/etc/nginx/includes/ssl.conf': '\ninclude /etc/nginx/zetcert/two.conf;' },
    );
    expect(d.errors).toEqual([
      {
        message:
          'the server block at /etc/nginx/nginx.conf:2 includes 2 zetcert certificates (one at /etc/nginx/nginx.conf:4, two at /etc/nginx/includes/ssl.conf:2): a server block uses one certificate',
        loc: { cert: 'two', exists: false, file: '/etc/nginx/includes/ssl.conf', line: 2 },
      },
    ]);
  });

  it('reports two snippets in http {} as an error too', () => {
    const d = run('http {\n  include /etc/nginx/zetcert/one.conf;\n  include /etc/nginx/zetcert/two.conf;\n  server { listen 443 ssl; server_name a.example; }\n}');
    expect(d.errors[0]?.message).toMatch(/^http \{\} at \/etc\/nginx\/nginx.conf:1 includes 2 zetcert certificates/);
  });

  it('lists skipped server names with file:line', () => {
    const d = run(`http {
  server {
    include /etc/nginx/zetcert/one.conf;
    server_name ok.example.com _ ~^re$ "" www.example.* localhost 10.0.0.1 $host bad_name.example.com;
  }
}`);
    expect(d.servers[0]?.names.map((n) => n.name)).toEqual(['ok.example.com']);
    expect(d.skipped.map((s) => [s.raw, s.warn, s.line])).toEqual([
      ['_', false, 4],
      ['~^re$', true, 4],
      ['', false, 4],
      ['www.example.*', true, 4],
      ['localhost', false, 4],
      ['10.0.0.1', false, 4],
      ['$host', false, 4],
      ['bad_name.example.com', true, 4],
    ]);
  });

  it('collects listen flags, stapling, support includes and other missing files', () => {
    const d = run(`http {
  include /etc/nginx/zetcert/_tls.conf;
  include /etc/nginx/missing.conf;
  ssl_stapling on;
  server {
    listen 443 ssl proxy_protocol;
    listen [::]:443 quic reuseport;
    listen 80;
    include /etc/nginx/zetcert/one.conf;
    ssl_stapling off;
  }
}`);
    expect(d.servers[0]?.listens.map((l) => [l.address, l.ssl, l.quic, l.proxyProtocol])).toEqual([
      ['443', true, false, true],
      ['[::]:443', false, true, false],
      ['80', false, false, false],
    ]);
    expect(d.stapling).toEqual([{ file: '/etc/nginx/nginx.conf', line: 4 }]);
    expect(d.supportIncludes).toEqual([{ path: '/etc/nginx/zetcert/_tls.conf', file: '/etc/nginx/nginx.conf', line: 2 }]);
    expect(d.missing.map((m) => m.path)).toEqual(['/etc/nginx/zetcert/_tls.conf', '/etc/nginx/missing.conf']);
  });

  it('rejects snippet names that are not valid certificate names', () => {
    const d = run('http { server { include /etc/nginx/zetcert/Bad_Name.conf; } }');
    expect(d.errors[0]?.message).toMatch(/invalid certificate name "Bad_Name"/);
    expect(d.snippetIncludes).toEqual([]);
  });

  it('warns about a glob include of the zetcert directory', () => {
    const d = run('http { server { include /etc/nginx/zetcert/*.conf; } }', {
      '/etc/nginx/zetcert/a.conf': '',
      '/etc/nginx/zetcert/_tls.conf': '',
    });
    expect(d.warnings[0]?.message).toMatch(/with a glob/);
    expect(d.snippetIncludes.map((s) => s.cert)).toEqual(['a']);
  });

  it('ignores server blocks outside http {}', () => {
    const d = run('stream { server { listen 443 ssl; include /etc/nginx/zetcert/tcp.conf; } }');
    expect(d.servers).toEqual([]);
    expect(d.snippetIncludes.map((s) => s.cert)).toEqual(['tcp']);
  });
});

describe('fixture: the store setup, with the snippet included from ssl.conf', () => {
  beforeEach(() => setRoot(path.join(__dirname, '../../fixtures/nginx/multisite')));
  afterEach(resetRoot);

  it('finds the names of every server block that includes ssl.conf', () => {
    const d = discover(loadNginxConfig('/etc/nginx/nginx.conf'));
    const used = d.servers.filter((s) => s.cert === 'store');
    expect(used.flatMap((s) => s.names.map((n) => `${n.name} ${path.basename(n.file)}:${n.line}`))).toEqual([
      'shop.store.example shop:4',
      'shop.store.example shop:4',
      'store.example store:18',
      'www.store.example store:18',
    ]);
    expect(d.skipped.filter((s) => s.warn).map((s) => s.raw)).toEqual(['~^(?<sub>.+)\\.shop\\.store\\.example$']);
    expect(d.skipped.filter((s) => !s.warn).map((s) => s.raw)).toEqual(['admin', 'localhost', '192.0.2.5', '_']);
    expect(d.errors).toEqual([]);
    expect(d.missing).toEqual([]);
  });
});
