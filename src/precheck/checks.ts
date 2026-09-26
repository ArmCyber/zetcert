// Pre-checks: free checks before Let's Encrypt is asked, so one broken name doesn't block a
// whole certificate. Nothing is sent to Let's Encrypt.
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { BlockList, isIP } from 'node:net';
import path from 'node:path';
import { isWildcard, parentOf } from '../certs/names';
import { isDirectory, makeDir, removeEmptyDir, removeFile, writeFileAtomic } from '../system/fs';
import { ACME_CONF } from '../nginx/support';
import { isCloudflare } from './cloudflare';
import type { CaaEntry, Lookup } from './lookup';

export interface CheckResult {
  ok: boolean;
  /** Why the name fails. */
  reason?: string;
  warnings: string[];
}

const pass = (warnings: string[] = []): CheckResult => ({ ok: true, warnings });
const fail = (reason: string, warnings: string[] = []): CheckResult => ({ ok: false, reason, warnings });

/** DNS: the A/AAAA records exist and every address is one of this server's public addresses. */
export async function checkAddresses(name: string, publicIps: string[], lookup: Lookup): Promise<CheckResult> {
  let addresses: string[];
  try {
    addresses = [...(await lookup.addresses(name, 4)), ...(await lookup.addresses(name, 6))];
  } catch (err) {
    return fail(`DNS lookup failed: ${(err as Error).message}`);
  }
  if (addresses.length === 0) return fail('no A/AAAA record');
  // A BlockList compares addresses, not their spelling (2001:DB8:0::1 is 2001:db8::1).
  const known = new BlockList();
  for (const ip of publicIps) known.addAddress(ip, isIP(ip) === 6 ? 'ipv6' : 'ipv4');
  const isKnown = (a: string) => isIP(a) !== 0 && known.check(a, isIP(a) === 6 ? 'ipv6' : 'ipv4');
  const warnings: string[] = [];
  const proxied = addresses.filter((a) => !isKnown(a) && isCloudflare(a));
  if (proxied.length > 0) warnings.push(`${name} is proxied through Cloudflare (${proxied.join(', ')})`);
  const elsewhere = addresses.filter((a) => !isKnown(a) && !isCloudflare(a));
  if (elsewhere.length === 0) return pass(warnings);
  const message = `points to ${elsewhere.join(', ')}, which isn't this server (${publicIps.join(', ') || 'no public address known'})`;
  if (!publicIps.some((ip) => isIP(ip) === 4)) {
    return pass([...warnings, `${name} ${message}; set public_ips in the config to check this`]);
  }
  return fail(message, warnings);
}

function parseAddress(address: string): { host: string; port: number } {
  const m = /^(\[([^\]]+)\]|[^:]+)(?::(\d+))?$/.exec(address);
  return { host: m?.[2] ?? m?.[1] ?? '127.0.0.1', port: m?.[3] ? Number(m[3]) : 80 };
}

function get(address: string, urlPath: string, hostHeader: string, timeoutMs: number) {
  const { host, port } = parseAddress(address);
  return new Promise<{ status: number; location?: string; body: string }>((resolve, reject) => {
    let settled = false;
    const finish = (err: Error | undefined, value?: { status: number; location?: string; body: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (err) reject(err);
      else resolve(value as { status: number; location?: string; body: string });
    };
    const req = http.get({ host, port, path: urlPath, headers: { Host: hostHeader }, timeout: timeoutMs }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        if (body.length < 4096) body += chunk;
      });
      res.on('error', (err) => finish(err));
      res.on('end', () => finish(undefined, { status: res.statusCode ?? 0, location: res.headers.location, body }));
      res.on('close', () => {
        if (!res.complete) finish(new Error('the connection closed before the answer was complete'));
      });
    });
    // An overall limit too: the idle timeout alone doesn't fire on every kind of stall.
    const deadline = setTimeout(() => req.destroy(new Error(`no complete answer within ${timeoutMs / 1000}s`)), timeoutMs);
    req.on('timeout', () => req.destroy(new Error(`no answer within ${timeoutMs / 1000}s`)));
    req.on('error', (err) => finish(err));
  });
}

/**
 * nginx: a temporary token file in the webroot, requested locally with the name as Host, so this
 * works behind NAT without NAT reflection.
 */
export async function checkHttp(name: string, webroot: string, httpAddress: string, timeoutMs = 10_000): Promise<CheckResult> {
  const token = `zetcert-precheck-${randomBytes(12).toString('hex')}`;
  const content = randomBytes(16).toString('hex');
  const dir = path.join(webroot, '.well-known', 'acme-challenge');
  const file = path.join(dir, token);
  // Directories created here get 0755 whatever the umask (nginx's workers must read them), and go
  // away afterwards, like certbot's own.
  const created: string[] = [];
  try {
    // Like certbot, create whatever is missing from the webroot down.
    const missing: string[] = [];
    for (let d = dir; !isDirectory(d) && d !== path.dirname(d); d = path.dirname(d)) missing.unshift(d);
    for (const d of missing) if (makeDir(d, 0o755)) created.push(d);
    writeFileAtomic(file, content, 0o644);
  } catch (err) {
    for (const d of created.reverse()) removeEmptyDir(d);
    return fail(`can't write a test file in ${dir}: ${(err as Error).message}`);
  }
  try {
    const r = await get(httpAddress, `/.well-known/acme-challenge/${token}`, name, timeoutMs);
    if (r.status >= 300 && r.status < 400) {
      return fail(
        `nginx redirects /.well-known/acme-challenge/ to ${r.location ?? 'another URL'}: serve it on port 80 without redirecting, e.g. include ${ACME_CONF}; in that server block`,
      );
    }
    if (r.status !== 200) return fail(`nginx answered HTTP ${r.status} for /.well-known/acme-challenge/ (webroot ${webroot})`);
    if (r.body.trim() !== content) return fail(`nginx doesn't serve /.well-known/acme-challenge/ from the webroot ${webroot}`);
    return pass();
  } catch (err) {
    return fail(`can't reach nginx at ${httpAddress}: ${(err as Error).message}`);
  } finally {
    removeFile(file);
    for (const d of created.reverse()) removeEmptyDir(d);
  }
}

const KNOWN_TAGS = new Set(['issue', 'issuewild', 'iodef', 'contactemail', 'contactphone', 'issuemail', 'issuevmc']);

function parseCaaValue(value: string): { issuer: string; params: Map<string, string> } {
  const [issuer = '', ...rest] = value.split(';');
  const params = new Map<string, string>();
  for (const part of rest) {
    const eq = part.indexOf('=');
    if (eq > 0) params.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  return { issuer: issuer.trim().toLowerCase(), params };
}

/**
 * CAA: the closest record set, climbing to parent names, must allow letsencrypt.org, the
 * validation method and the account. For a wildcard, `issuewild` decides when there is one.
 */
export async function checkCaa(
  name: string,
  method: 'http-01' | 'dns-01',
  accountUris: string[],
  lookup: Lookup,
): Promise<CheckResult> {
  const wildcard = isWildcard(name);
  let domain = wildcard ? parentOf(name) : name;
  let records: CaaEntry[];
  for (;;) {
    try {
      records = await lookup.caa(domain);
    } catch (err) {
      return fail(`CAA lookup for ${domain} failed: ${(err as Error).message}`);
    }
    if (records.length > 0 || !domain.includes('.')) break;
    domain = parentOf(domain);
  }
  if (records.length === 0) return pass();

  const critical = records.find((r) => r.critical & 128 && !KNOWN_TAGS.has(r.tag));
  if (critical) return fail(`the CAA records of ${domain} have a critical property zetcert doesn't know: ${critical.tag}`);
  const issuewild = records.filter((r) => r.tag === 'issuewild');
  const relevant = wildcard && issuewild.length > 0 ? issuewild : records.filter((r) => r.tag === 'issue');
  if (relevant.length === 0) return pass();

  for (const record of relevant) {
    const { issuer, params } = parseCaaValue(record.value);
    if (issuer !== 'letsencrypt.org') continue;
    const methods = params.get('validationmethods');
    if (methods && !methods.split(',').map((m) => m.trim()).includes(method)) continue;
    const account = params.get('accounturi');
    if (account && !accountUris.includes(account)) continue;
    return pass();
  }
  const tag = relevant[0]?.tag ?? 'issue';
  return fail(
    `the CAA records of ${domain} don't allow Let's Encrypt${tag === 'issuewild' ? ' for wildcards' : ''} with ${method}${
      accountUris.length > 0 ? ' and this account' : ''
    }: ${relevant.map((r) => `${r.tag} "${r.value}"`).join(', ')}`,
  );
}
