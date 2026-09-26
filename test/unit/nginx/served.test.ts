import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parseCert } from '../../../src/certbot/reader';
import { discover } from '../../../src/nginx/discovery';
import { loadNginxConfig } from '../../../src/nginx/include';
import { checkServed, listenEndpoint, type ServedTarget, servedTargets } from '../../../src/nginx/served';
import { snippetContent } from '../../../src/nginx/snippets';
import { readText } from '../../../src/system/fs';
import { makeCert } from '../certs-helper';
import { tempRoot } from '../helpers';

describe('listenEndpoint', () => {
  it.each([
    ['443', { host: '127.0.0.1', port: 443 }],
    ['*:443', { host: '127.0.0.1', port: 443 }],
    ['0.0.0.0:8443', { host: '127.0.0.1', port: 8443 }],
    ['[::]:443', { host: '::1', port: 443 }],
    ['[2001:db8::1]:443', { host: '2001:db8::1', port: 443 }],
    ['10.0.0.1:443', { host: '10.0.0.1', port: 443 }],
    ['10.0.0.1', { host: '10.0.0.1', port: 80 }],
    ['localhost:443', { host: 'localhost', port: 443 }],
    ['unix:/run/nginx.sock', { socketPath: '/run/nginx.sock' }],
  ])('%s', (address, endpoint) => expect(listenEndpoint(address)).toEqual(endpoint));
});

describe('servedTargets', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('lists each SSL address and name of blocks using zetcert certificates', () => {
    const cert = makeCert({ names: ['a.example'] });
    root.write('/etc/letsencrypt/live/a/fullchain.pem', cert.pem);
    root.write('/etc/nginx/zetcert/a.conf', snippetContent('a', true));
    root.write(
      '/etc/nginx/nginx.conf',
      `http {
  server { listen 443 ssl; listen [::]:443 ssl; listen 80; server_name a.example www.a.example *.a.example; include /etc/nginx/zetcert/a.conf; }
  server { listen 8443 ssl proxy_protocol; server_name a.example; include /etc/nginx/zetcert/a.conf; }
  server { listen 443 ssl; server_name other.example; ssl_certificate /x.pem; }
}`,
    );
    const targets = servedTargets(discover(loadNginxConfig('/etc/nginx/nginx.conf')), (c) => readText(`/etc/nginx/zetcert/${c}.conf`));
    expect(targets.map((t) => [t.address, t.name, t.proxyProtocol])).toEqual([
      ['443', 'a.example', false],
      ['443', 'www.a.example', false],
      ['[::]:443', 'a.example', false],
      ['[::]:443', 'www.a.example', false],
      ['8443', 'a.example', true],
    ]);
    expect(targets[0]?.expectedPath).toBe('/etc/letsencrypt/live/a/fullchain.pem');
    expect(targets[0]?.expected?.fingerprint).toBe(parseCert(cert.pem).fingerprint);
  });
});

describe('checkServed', () => {
  const good = makeCert({ names: ['good.test'] });
  const other = makeCert({ names: ['other.test'] });
  const servers: { close(): unknown }[] = [];
  let tlsPort = 0;
  let proxyPort = 0;
  let proxyLine = '';
  const socketPath = path.join(tmpdir(), `zetcert-served-${process.pid}.sock`);

  const tlsServer = () =>
    tls.createServer({
      cert: other.pem,
      key: other.key,
      SNICallback: (name, cb) =>
        cb(null, tls.createSecureContext(name === 'good.test' ? { cert: good.pem, key: good.key } : { cert: other.pem, key: other.key })),
    });

  beforeAll(async () => {
    const plain = tlsServer();
    await new Promise<void>((r) => plain.listen(0, '127.0.0.1', r));
    tlsPort = (plain.address() as net.AddressInfo).port;
    // A PROXY-protocol listener: reads the header line, then hands the socket to TLS.
    const inner = tlsServer();
    const proxy = net.createServer((socket) => {
      socket.once('data', (chunk) => {
        socket.pause();
        const end = chunk.indexOf('\r\n');
        proxyLine = chunk.subarray(0, end).toString();
        socket.unshift(chunk.subarray(end + 2));
        inner.emit('connection', socket);
      });
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    proxyPort = (proxy.address() as net.AddressInfo).port;
    const unix = tlsServer();
    await new Promise<void>((r) => unix.listen(socketPath, r));
    servers.push(plain, proxy, unix);
  });
  afterAll(() => servers.forEach((s) => s.close()));

  const target = (extra: Partial<ServedTarget>): ServedTarget => ({
    cert: 'good',
    address: '443',
    endpoint: { host: '127.0.0.1', port: tlsPort },
    proxyProtocol: false,
    name: 'good.test',
    listen: { file: '/etc/nginx/nginx.conf', line: 1 },
    expected: parseCert(good.pem),
    ...extra,
  });

  it('compares the served certificate with the file', async () => {
    const [ok, mismatch] = await checkServed([target({}), target({ name: 'unknown.test' })]);
    expect(ok?.status).toBe('ok');
    expect(mismatch?.status).toBe('mismatch');
    expect(mismatch?.served?.names).toEqual(['other.test']);
  });

  it('sends a PROXY v1 header first on proxy_protocol listeners', async () => {
    const [result] = await checkServed([target({ endpoint: { host: '127.0.0.1', port: proxyPort }, proxyProtocol: true })]);
    expect(result?.status).toBe('ok');
    expect(proxyLine).toMatch(/^PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 \d+ \d+$/);
  });

  it('connects to unix sockets', async () => {
    const [result] = await checkServed([target({ endpoint: { socketPath } })]);
    expect(result?.status).toBe('ok');
  });

  it('reports what it could not check', async () => {
    const closed = net.createServer();
    await new Promise<void>((r) => closed.listen(0, '127.0.0.1', r));
    const port = (closed.address() as net.AddressInfo).port;
    closed.close();
    const [result] = await checkServed([target({ endpoint: { host: '127.0.0.1', port } })]);
    expect(result?.status).toBe('error');
    expect(result?.error).toMatch(/ECONNREFUSED/);
  });
});
