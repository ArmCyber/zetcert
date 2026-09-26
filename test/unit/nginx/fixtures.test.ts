import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { discover } from '../../../src/nginx/discovery';
import { loadNginxConfig } from '../../../src/nginx/include';
import { resetRoot, setRoot } from '../../../src/system/paths';

const fixture = (name: string) => path.join(__dirname, '../../fixtures/nginx', name);

describe('fixture: OpenResty with Lua blocks', () => {
  afterEach(resetRoot);

  it('parses Lua blocks, variables and quotes, and finds the snippets through nested includes', () => {
    setRoot(fixture('openresty'));
    const config = loadNginxConfig('/usr/local/openresty/nginx/conf/nginx.conf');
    const http = config.directives.find((d) => d.name === 'http');
    const init = http?.block?.find((d) => d.name === 'init_by_lua_block');
    expect(init?.lua).toContain('server { this is not nginx }');
    const logFormat = http?.block?.find((d) => d.name === 'log_format');
    expect(logFormat?.args).toEqual(['main', '$remote_addr - "${request}" \'quoted\' "$status"']);
    const d = discover(config);
    expect(d.servers.map((s) => [s.names[0]?.name, s.cert])).toEqual([
      ['api.example.com', 'api'],
      ['static.example.com', 'api'],
    ]);
    // Relative includes resolve against the main config's directory.
    expect(config.files).toContain('/usr/local/openresty/nginx/conf/ssl-params.conf');
    expect(d.errors).toEqual([]);
  });
});

describe('fixture: broken files', () => {
  afterEach(resetRoot);

  it.each([
    ['missing-semicolon.conf', 'missing-semicolon.conf:4: unexpected "}"'],
    ['unclosed-block.conf', 'unclosed-block.conf:3: unexpected end of file, expecting "}"'],
    ['extra-brace.conf', 'extra-brace.conf:4: unexpected "}"'],
    ['unterminated-quote.conf', 'unterminated-quote.conf:2: unexpected end of file, expecting ";" or "}"'],
    ['unclosed-lua.conf', 'unclosed-lua.conf:5: unexpected end of file in a Lua block'],
    ['cycle-a.conf', 'cycle-b.conf:2: include cycle: /cycle-a.conf → /cycle-b.conf → /cycle-a.conf'],
  ])('%s', (file, message) => {
    setRoot(fixture('broken'));
    expect(() => loadNginxConfig(`/${file}`)).toThrow(message);
  });
});
