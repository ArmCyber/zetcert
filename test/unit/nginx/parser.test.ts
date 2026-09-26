import { mkdirSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { expandGlob, loadNginxConfig } from '../../../src/nginx/include';
import { tokenize } from '../../../src/nginx/lexer';
import { type Directive, parse } from '../../../src/nginx/parser';
import { resetRoot, setRoot } from '../../../src/system/paths';
import { tempRoot } from '../helpers';

const words = (text: string) => tokenize(text).map((t) => ('value' in t ? t.value : t.type));

/** name args… per directive, flattened with blocks in braces, for compact assertions. */
function outline(directives: Directive[]): string[] {
  return directives.flatMap((d) => [
    [d.name, ...d.args].join(' ') + (d.block ? ' {' : d.lua !== undefined ? ' {lua}' : ''),
    ...(d.block ? [...outline(d.block), '}'] : []),
    ...(d.include ?? []).flatMap((f) => [`  <${f.path}>`, ...outline(f.directives).map((l) => `  ${l}`)]),
  ]);
}

describe('lexer', () => {
  it('splits words, semicolons and braces', () => {
    expect(words('server { listen 443 ssl; }')).toEqual(['server', '{', 'listen', '443', 'ssl', ';', '}']);
  });

  it('handles comments only where a token starts', () => {
    expect(words('a b; # comment ; {\nc d#e;')).toEqual(['a', 'b', ';', 'c', 'd#e', ';']);
  });

  it('handles quotes and escapes like nginx', () => {
    expect(() => words(`a 'it''s';`)).toThrow('unexpected "\'"');
    expect(words(`add_header X "a \\"b\\" \\\\ \\t" 'c\\'d';`)).toEqual(['add_header', 'X', 'a "b" \\ \t', "c'd", ';']);
    expect(words('a \\x\\;b;')).toEqual(['a', '\\x\\;b', ';']);
    expect(words('a "multi\nline";')).toEqual(['a', 'multi\nline', ';']);
  });

  it("doesn't end a word at } and keeps ${var} together", () => {
    expect(words('set $a ${b}c;')).toEqual(['set', '$a', '${b}c', ';']);
    expect(words('return 200 "${host}";')).toEqual(['return', '200', '${host}', ';']);
    expect(words('if ($x) {return 403;}')).toEqual(['if', '($x)', '{', 'return', '403', ';', '}']);
  });

  it('reads *_by_lua_block bodies as Lua', () => {
    const tokens = tokenize(`content_by_lua_block {
      local s = "}" -- a } in a comment
      local t = [[ } ]] --[==[ } ]==]
      if x then ngx.say('{') end
      local u = { a = { } }
    }
    next;`);
    expect(tokens.map((t) => t.type)).toEqual(['word', '{', 'lua', '}', 'word', ';']);
    expect(tokens[5]).toEqual({ type: ';', line: 7 });
  });

  it('tracks line numbers', () => {
    const tokens = tokenize('a;\n\n  b "x\ny" c;\nd;');
    expect(tokens.filter((t) => t.type === 'word').map((t) => [('value' in t && t.value) || '', t.line])).toEqual([
      ['a', 1],
      ['b', 3],
      ['x\ny', 3],
      ['c', 4],
      ['d', 5],
    ]);
  });

  it('reports syntax errors with the line', () => {
    expect(() => tokenize('a;\n;')).toThrow('unexpected ";"');
    expect(() => tokenize('a "x"y;')).toThrow('unexpected "y"');
    expect(() => tokenize('a "x')).toThrow('unexpected end of file');
    expect(() => tokenize('a b }')).toThrow('unexpected "}"');
  });
});

describe('parser', () => {
  it('builds directives with blocks, file and line', () => {
    const tree = parse('http {\n  server {\n    listen 443 ssl;\n  }\n}\n', '/etc/nginx/nginx.conf');
    expect(outline(tree)).toEqual(['http {', 'server {', 'listen 443 ssl', '}', '}']);
    const listen = tree[0]?.block?.[0]?.block?.[0];
    expect(listen).toMatchObject({ name: 'listen', args: ['443', 'ssl'], file: '/etc/nginx/nginx.conf', line: 3 });
  });

  it('keeps Lua blocks as code', () => {
    const tree = parse('location / {\n  access_by_lua_block { if a then b() end }\n  return 200;\n}', 'f');
    expect(tree[0]?.block?.[0]).toMatchObject({ name: 'access_by_lua_block', lua: ' if a then b() end ' });
    expect(tree[0]?.block?.[1]).toMatchObject({ name: 'return', line: 3 });
  });

  it('reports broken files with file:line', () => {
    expect(() => parse('http {\n  a;\n', 'f.conf')).toThrow('f.conf:2: unexpected end of file, expecting "}"');
    expect(() => parse('a b', 'f.conf')).toThrow('f.conf:1: unexpected end of file, expecting ";" or "}"');
    expect(() => parse('a;\n}', 'f.conf')).toThrow('f.conf:2: unexpected "}"');
  });
});

describe('include resolution', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('follows includes relative to the main config, with sorted globs', () => {
    root.write('/etc/nginx/nginx.conf', 'http {\n  include conf.d/*.conf;\n  include /etc/nginx/sites-enabled/*;\n}\n');
    root.write('/etc/nginx/conf.d/b.conf', 'b;');
    root.write('/etc/nginx/conf.d/a.conf', 'a;');
    root.write('/etc/nginx/conf.d/c.txt', 'no;');
    root.write('/etc/nginx/conf.d/.hidden.conf', 'no;');
    root.write('/etc/nginx/sites-enabled/shop', 'server { include snippets/x.conf; }');
    root.write('/etc/nginx/snippets/x.conf', 'x;');
    const config = loadNginxConfig('/etc/nginx/nginx.conf');
    expect(outline(config.directives)).toEqual([
      'http {',
      'include conf.d/*.conf',
      '  </etc/nginx/conf.d/a.conf>',
      '  a',
      '  </etc/nginx/conf.d/b.conf>',
      '  b',
      'include /etc/nginx/sites-enabled/*',
      '  </etc/nginx/sites-enabled/shop>',
      '  server {',
      '  include snippets/x.conf',
      '    </etc/nginx/snippets/x.conf>',
      '    x',
      '  }',
      '}',
    ]);
    expect(config.missing).toEqual([]);
  });

  it('records missing files instead of aborting', () => {
    root.write('/etc/nginx/nginx.conf', 'http {\n  server {\n    include /etc/nginx/zetcert/store.conf;\n  }\n  include /etc/nginx/none/*.conf;\n}\n');
    const config = loadNginxConfig('/etc/nginx/nginx.conf');
    expect(config.missing).toEqual([
      { path: '/etc/nginx/zetcert/store.conf', file: '/etc/nginx/nginx.conf', line: 3 },
    ]);
  });

  it('detects include cycles', () => {
    root.write('/etc/nginx/nginx.conf', 'include a.conf;');
    root.write('/etc/nginx/a.conf', 'include b.conf;');
    root.write('/etc/nginx/b.conf', '\ninclude a.conf;');
    expect(() => loadNginxConfig('/etc/nginx/nginx.conf')).toThrow(
      '/etc/nginx/b.conf:2: include cycle: /etc/nginx/nginx.conf → /etc/nginx/a.conf → /etc/nginx/b.conf → /etc/nginx/a.conf',
    );
  });

  it('reports syntax errors in included files', () => {
    root.write('/etc/nginx/nginx.conf', 'include a.conf;');
    root.write('/etc/nginx/a.conf', 'server {\n  listen 80\n}');
    expect(() => loadNginxConfig('/etc/nginx/nginx.conf')).toThrow('/etc/nginx/a.conf:3: unexpected "}"');
  });

  it('fails clearly without a main config', () => {
    expect(() => loadNginxConfig('/etc/nginx/nginx.conf')).toThrow("the nginx config /etc/nginx/nginx.conf doesn't exist");
  });

  it('expands globs in directories too', () => {
    root.write('/etc/nginx/apps/one/site.conf', '');
    root.write('/etc/nginx/apps/two/site.conf', '');
    root.write('/etc/nginx/apps/two/other.conf', '');
    expect(expandGlob('/etc/nginx/apps/*/site.conf')).toEqual(['/etc/nginx/apps/one/site.conf', '/etc/nginx/apps/two/site.conf']);
    expect(expandGlob('/etc/nginx/apps/t[vw]o/[!s]*.conf')).toEqual(['/etc/nginx/apps/two/other.conf']);
  });
});

describe('fixture: Debian 13 default config', () => {
  beforeEach(() => setRoot(path.join(__dirname, '../../fixtures/nginx/debian13')));
  afterEach(resetRoot);

  it('parses nginx.conf and the default site through its absolute symlink', () => {
    const config = loadNginxConfig('/etc/nginx/nginx.conf');
    expect(config.files).toEqual([
      '/etc/nginx/nginx.conf',
      '/etc/nginx/mime.types',
      '/etc/nginx/sites-enabled/default',
    ]);
    expect(config.missing).toEqual([]);
    const http = config.directives.find((d) => d.name === 'http');
    const sites = http?.block?.find((d) => d.args[0] === '/etc/nginx/sites-enabled/*');
    const server = sites?.include?.[0]?.directives.find((d) => d.name === 'server');
    expect(server?.block?.find((d) => d.name === 'server_name')).toMatchObject({ args: ['_'], line: 46 });
  });
});

describe('includes nginx fails on', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('records a dangling link matched by a glob as missing', () => {
    root.write('/etc/nginx/nginx.conf', 'http {\n  include /etc/nginx/sites-enabled/*;\n}\n');
    root.write('/etc/nginx/sites-enabled/shop', 'server { }');
    symlinkSync('/etc/nginx/sites-available/gone', root.path('/etc/nginx/sites-enabled/gone'));
    const config = loadNginxConfig('/etc/nginx/nginx.conf');
    expect(config.missing).toEqual([{ path: '/etc/nginx/sites-enabled/gone', file: '/etc/nginx/nginx.conf', line: 2 }]);
    expect(config.files).toContain('/etc/nginx/sites-enabled/shop');
  });

  it('reports an included directory at the include', () => {
    root.write('/etc/nginx/nginx.conf', 'http {\n  include /etc/nginx/conf.d;\n}\n');
    root.write('/etc/nginx/conf.d/a.conf', '');
    expect(() => loadNginxConfig('/etc/nginx/nginx.conf')).toThrow('/etc/nginx/nginx.conf:2: /etc/nginx/conf.d is a directory');
    root.write('/etc/nginx/nginx.conf', 'http {\n  include /etc/nginx/*;\n}\n');
    expect(() => loadNginxConfig('/etc/nginx/nginx.conf')).toThrow('/etc/nginx/conf.d is a directory');
  });

  it('follows a link whose parent directory is itself a link', () => {
    root.write('/srv/nginx/available/shop', 'server { server_name shop.example.com; }');
    mkdirSync(root.path('/srv/nginx/enabled'), { recursive: true });
    symlinkSync('../available/shop', root.path('/srv/nginx/enabled/shop'));
    root.write('/etc/nginx/nginx.conf', 'http {\n  include /etc/nginx/sites-enabled/*;\n}\n');
    symlinkSync('../../srv/nginx/enabled', root.path('/etc/nginx/sites-enabled'));
    const config = loadNginxConfig('/etc/nginx/nginx.conf');
    expect(config.files).toEqual(['/etc/nginx/nginx.conf', '/etc/nginx/sites-enabled/shop']);
    expect(config.missing).toEqual([]);
  });
});
