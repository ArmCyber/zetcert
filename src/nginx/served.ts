// Does nginx serve the certificate on disk? A TLS handshake to each `listen … ssl` address with each
// name as SNI, compared with the file the snippet points to. This catches a missed reload or a
// wrong include.
import { X509Certificate } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import { type CertFile, readCertFile } from '../certbot/reader';
import { isWildcard } from '../certs/names';
import type { Loc } from '../system/loc';
import type { Discovery } from './discovery';

export interface Endpoint {
  host?: string;
  port?: number;
  socketPath?: string;
}

export interface ServedTarget {
  cert: string;
  /** The listen address as written. */
  address: string;
  endpoint: Endpoint;
  proxyProtocol: boolean;
  /** The SNI name. */
  name: string;
  listen: Loc;
  /** The certificate file the snippet points to, and its certificate. */
  expectedPath?: string;
  expected?: CertFile;
}

export interface ServedResult extends ServedTarget {
  /** `no-file`: the snippet or the certificate file it points to is missing, so there is nothing to compare. */
  status: 'ok' | 'mismatch' | 'error' | 'no-file';
  served?: { fingerprint: string; subject: string; names: string[]; notAfter: Date };
  error?: string;
}

/** Where to connect for a `listen` address; wildcard addresses mean localhost. */
export function listenEndpoint(address: string): Endpoint | undefined {
  if (address.startsWith('unix:')) return { socketPath: address.slice('unix:'.length) };
  if (/^\d+$/.test(address)) return { host: '127.0.0.1', port: Number(address) };
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(address);
  if (v6) {
    const ip = v6[1] as string;
    return { host: ip === '::' ? '::1' : ip, port: v6[2] ? Number(v6[2]) : 80 };
  }
  const other = /^([^:[\]]+)(?::(\d+))?$/.exec(address);
  if (other) {
    const host = other[1] as string;
    return { host: host === '*' || host === '0.0.0.0' ? '127.0.0.1' : host, port: other[2] ? Number(other[2]) : 80 };
  }
  return undefined;
}

/** The certificate path in a snippet's `ssl_certificate` line. */
export function snippetCertPath(snippet: string | undefined): string | undefined {
  return /^\s*ssl_certificate\s+([^\s;]+)\s*;/m.exec(snippet ?? '')?.[1];
}

/**
 * One target per SSL listen address and name of every server block that uses a zetcert certificate.
 * Wildcard names are left out: there's no single name to send.
 */
export function servedTargets(discovery: Discovery, snippetOf: (cert: string) => string | undefined): ServedTarget[] {
  const targets = new Map<string, ServedTarget>();
  for (const server of discovery.servers) {
    if (!server.cert) continue;
    const expectedPath = snippetCertPath(snippetOf(server.cert));
    let expected: CertFile | undefined;
    try {
      expected = expectedPath ? readCertFile(expectedPath) : undefined;
    } catch {
      expected = undefined;
    }
    for (const listen of server.listens.filter((l) => l.ssl)) {
      const endpoint = listenEndpoint(listen.address);
      if (!endpoint) continue;
      for (const { name } of server.names.filter((n) => !isWildcard(n.name))) {
        const key = `${endpoint.socketPath ?? `${endpoint.host}:${endpoint.port}`} ${name}`;
        if (targets.has(key)) continue;
        targets.set(key, {
          cert: server.cert,
          address: listen.address,
          endpoint,
          proxyProtocol: listen.proxyProtocol,
          name,
          listen: { file: listen.file, line: listen.line },
          expectedPath,
          expected,
        });
      }
    }
  }
  return [...targets.values()];
}

function proxyHeader(socket: net.Socket): string {
  const family = socket.remoteFamily;
  if (family !== 'IPv4' && family !== 'IPv6') return 'PROXY UNKNOWN\r\n';
  return `PROXY ${family === 'IPv4' ? 'TCP4' : 'TCP6'} ${socket.localAddress} ${socket.remoteAddress} ${socket.localPort} ${socket.remotePort}\r\n`;
}

/** The leaf certificate served for `name`. */
export function fetchServedCert(target: ServedTarget, timeoutMs: number): Promise<X509Certificate> {
  return new Promise((resolve, reject) => {
    const { endpoint } = target;
    const raw = endpoint.socketPath
      ? net.connect({ path: endpoint.socketPath })
      : net.connect({ host: endpoint.host, port: endpoint.port ?? 443 });
    let settled = false;
    const finish = (err: Error | undefined, cert?: X509Certificate) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      raw.destroy();
      if (err) reject(err);
      else resolve(cert as X509Certificate);
    };
    const timer = setTimeout(() => finish(new Error(`no answer within ${timeoutMs / 1000}s`)), timeoutMs);
    raw.on('error', (err) => finish(err));
    raw.on('connect', () => {
      if (target.proxyProtocol) raw.write(proxyHeader(raw));
      const secure = tls.connect({ socket: raw, servername: target.name, rejectUnauthorized: false });
      secure.on('error', (err) => finish(err));
      secure.on('secureConnect', () => {
        const peer = secure.getPeerCertificate();
        secure.destroy();
        if (!peer?.raw) finish(new Error('no certificate served'));
        else finish(undefined, new X509Certificate(peer.raw));
      });
    });
  });
}

export async function checkServed(targets: ServedTarget[], timeoutMs = 5000, concurrency = 8): Promise<ServedResult[]> {
  const results: ServedResult[] = new Array(targets.length);
  let next = 0;
  const worker = async () => {
    while (next < targets.length) {
      const i = next++;
      const target = targets[i] as ServedTarget;
      try {
        const x509 = await fetchServedCert(target, timeoutMs);
        const served = {
          fingerprint: x509.fingerprint256,
          // Let's Encrypt certificates may have an empty subject: then Node gives undefined.
          subject: x509.subject ?? '',
          names: (x509.subjectAltName ?? '')
            .split(', ')
            .filter((n) => n.startsWith('DNS:'))
            .map((n) => n.slice(4)),
          notAfter: new Date(x509.validTo),
        };
        const status = !target.expected ? 'no-file' : served.fingerprint === target.expected.fingerprint ? 'ok' : 'mismatch';
        results[i] = { ...target, status, served };
      } catch (err) {
        results[i] = { ...target, status: 'error', error: (err as Error).message };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
  return results;
}
