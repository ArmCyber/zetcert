// What certbot has: its certificates (/etc/letsencrypt/live) and how it renews them
// (/etc/letsencrypt/renewal/<cert>.conf).
import { X509Certificate } from 'node:crypto';
import { exec } from '../system/exec';
import { listDir, readText } from '../system/fs';
import { LETSENCRYPT_DIR } from '../system/paths';
import { parseConfigObj, type Section, type Value } from './configobj';

export const LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
const STAGING_SERVERS = [LE_STAGING, 'https://acme-staging.api.letsencrypt.org/directory'];

export interface CertFile {
  names: string[];
  notBefore: Date;
  notAfter: Date;
  issuer: string;
  /** ecdsa or rsa (or another key algorithm as Node names it). */
  keyType: string;
  fingerprint: string;
  serial: string;
}

export interface RenewalSettings {
  authenticator?: string;
  installer?: string;
  webrootPath: string[];
  webrootMap: Record<string, string>;
  server?: string;
  keyType?: string;
  account?: string;
  prefChalls: string[];
  manualAuthHook?: string;
  manualCleanupHook?: string;
  /** `--deploy-hook`, saved as renew_hook, or deploy_hook in newer certbot. */
  deployHook?: string;
  preHook?: string;
  postHook?: string;
}

export interface CertbotCert {
  name: string;
  /** The leaf certificate from live/<name>/cert.pem; undefined when it can't be read. */
  cert?: CertFile;
  renewal: RenewalSettings;
  /** Let's Encrypt's staging URL, or a "(STAGING)" issuer. */
  staging: boolean;
}

export function livePath(cert: string, file: 'cert.pem' | 'fullchain.pem' | 'privkey.pem' | 'chain.pem'): string {
  return `${LETSENCRYPT_DIR}/live/${cert}/${file}`;
}

export function renewalPath(cert: string): string {
  return `${LETSENCRYPT_DIR}/renewal/${cert}.conf`;
}

/** Reads the first certificate of a PEM file. */
export function readCertFile(path: string): CertFile | undefined {
  const pem = readText(path);
  if (pem === undefined) return undefined;
  const first = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
  if (!first) return undefined;
  return parseCert(first[0]);
}

export function parseCert(pem: string | Buffer): CertFile {
  const x509 = new X509Certificate(pem);
  const names = (x509.subjectAltName ?? '')
    .split(', ')
    .filter((entry) => entry.startsWith('DNS:'))
    .map((entry) => entry.slice(4).toLowerCase());
  const keyType = x509.publicKey.asymmetricKeyType;
  return {
    names,
    notBefore: new Date(x509.validFrom),
    notAfter: new Date(x509.validTo),
    issuer: x509.issuer,
    keyType: keyType === 'ec' ? 'ecdsa' : (keyType ?? 'unknown'),
    fingerprint: x509.fingerprint256,
    serial: x509.serialNumber,
  };
}

function str(value: Value | undefined): string | undefined {
  if (value === undefined) return undefined;
  const s = Array.isArray(value) ? value.join(',') : value;
  return s === '' || s === 'None' ? undefined : s;
}

function list(value: Value | undefined): string[] {
  if (value === undefined) return [];
  return (Array.isArray(value) ? value : [value]).filter((v) => v !== '' && v !== 'None');
}

export function parseRenewal(text: string): RenewalSettings {
  const root = parseConfigObj(text);
  const params: Section = root.sections.renewalparams ?? { values: {}, sections: {} };
  const v = params.values;
  const map = params.sections.webroot_map?.values ?? {};
  return {
    authenticator: str(v.authenticator),
    installer: str(v.installer),
    webrootPath: list(v.webroot_path),
    webrootMap: Object.fromEntries(Object.entries(map).map(([k, value]) => [k, str(value) ?? ''])),
    server: str(v.server),
    keyType: str(v.key_type),
    account: str(v.account),
    prefChalls: list(v.pref_challs),
    manualAuthHook: str(v.manual_auth_hook),
    manualCleanupHook: str(v.manual_cleanup_hook),
    deployHook: str(v.deploy_hook) ?? str(v.renew_hook),
    preHook: str(v.pre_hook),
    postHook: str(v.post_hook),
  };
}

export function isStaging(server: string | undefined, issuer: string | undefined): boolean {
  return (server !== undefined && STAGING_SERVERS.includes(server)) || (issuer?.includes('(STAGING)') ?? false);
}

export function readCertbotCert(name: string): CertbotCert | undefined {
  const text = readText(renewalPath(name));
  if (text === undefined) return undefined;
  const renewal = parseRenewal(text);
  let cert: CertFile | undefined;
  try {
    cert = readCertFile(livePath(name, 'cert.pem'));
  } catch {
    cert = undefined;
  }
  return { name, cert, renewal, staging: isStaging(renewal.server, cert?.issuer) };
}

/** Every certificate certbot has, by the renewal files that define them. */
export function readCertbotCerts(): CertbotCert[] {
  return listDir(`${LETSENCRYPT_DIR}/renewal`)
    .filter((f) => f.endsWith('.conf'))
    .map((f) => readCertbotCert(f.slice(0, -'.conf'.length)))
    .filter((c): c is CertbotCert => c !== undefined);
}

export interface CertbotVersion {
  major: number;
  minor: number;
  patch: number;
  text: string;
}

export function parseCertbotVersion(output: string): CertbotVersion | undefined {
  const m = /certbot (\d+)\.(\d+)\.(\d+)/.exec(output);
  if (!m) return undefined;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), text: `${m[1]}.${m[2]}.${m[3]}` };
}

export function versionAtLeast(v: CertbotVersion, major: number, minor: number): boolean {
  return v.major > major || (v.major === major && v.minor >= minor);
}

/** `certbot --version`; undefined when certbot isn't installed. Old versions print it on stderr. */
export async function certbotVersion(): Promise<CertbotVersion | undefined> {
  try {
    const r = await exec('certbot', ['--version'], { timeoutMs: 60_000 });
    return parseCertbotVersion(`${r.stdout}\n${r.stderr}`);
  } catch {
    return undefined;
  }
}

/** certbot's ACME accounts: id → account URI, from accounts/<server>/<id>/regr.json. */
export function readAccounts(): Map<string, string> {
  const accounts = new Map<string, string>();
  const walk = (dir: string, depth: number) => {
    for (const entry of listDir(dir)) {
      const p = `${dir}/${entry}`;
      if (entry === 'regr.json') {
        try {
          const uri = (JSON.parse(readText(p) ?? '{}') as { uri?: unknown }).uri;
          if (typeof uri === 'string') accounts.set(dir.slice(dir.lastIndexOf('/') + 1), uri);
        } catch {
          // not an account
        }
      } else if (depth < 5) {
        walk(p, depth + 1);
      }
    }
  };
  walk(`${LETSENCRYPT_DIR}/accounts`, 0);
  return accounts;
}
