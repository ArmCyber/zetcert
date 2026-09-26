// /etc/zetcert/config.yml: load, validate and fill in the defaults.
import { isIP } from 'node:net';
import path from 'node:path';
import { type Document, LineCounter, parseDocument } from 'yaml';
import { isWildcard, normalizeCertName } from '../certs/names';
import { UserError } from '../system/errors';
import { readText } from '../system/fs';
import { NGINX_CONFIG } from '../system/paths';
import { isValidName, NAME_RULE, wildcardDomain } from './names';

export const KEY_TYPES = ['ecdsa', 'rsa'] as const;
export type KeyType = (typeof KEY_TYPES)[number];

export const CHALLENGES = ['auto', 'http', 'dns'] as const;
export type Challenge = (typeof CHALLENGES)[number];

export const TLS_KEYS = [
  'protocols',
  'ciphers',
  'prefer_server_ciphers',
  'session_cache',
  'session_timeout',
  'session_tickets',
  'dhparam',
] as const;
export type TlsKey = (typeof TLS_KEYS)[number];
/** Only the values set in the config; the rest follow zetcert's defaults. */
export type TlsOverrides = Partial<Record<TlsKey, string>>;

export interface CertConfig {
  names: string[];
  exclude: string[];
  challenge: Challenge;
  dns?: string;
  key_type?: KeyType;
  deploy: string[];
}

export interface Config {
  email?: string;
  webroot: string;
  public_ips: string[];
  key_type: KeyType;
  tls: TlsOverrides | 'off';
  nginx: { config: string; test: string; reload: string };
  precheck: { http_address: string };
  /** Seconds. */
  dns_propagation_timeout: number;
  /** Empty: no alerts. */
  notify: string;
  certs: Record<string, CertConfig>;
}

export function defaultConfig(): Config {
  return {
    webroot: '/var/www/html',
    public_ips: [],
    key_type: 'ecdsa',
    tls: {},
    nginx: { config: NGINX_CONFIG, test: 'nginx -t', reload: 'systemctl reload nginx' },
    precheck: { http_address: '127.0.0.1:80' },
    dns_propagation_timeout: 180,
    notify: '',
    certs: {},
  };
}

export function defaultCertConfig(): CertConfig {
  return { names: [], exclude: [], challenge: 'auto', deploy: [] };
}

export interface LoadedConfig {
  path: string;
  /** False before `init` has created the file; the config is then all defaults. */
  exists: boolean;
  config: Config;
  /** The parsed file, kept so edits can preserve its comments. */
  doc: Document;
}

type KeyPath = (string | number)[];

const TOP_KEYS = [
  'email',
  'webroot',
  'public_ips',
  'key_type',
  'tls',
  'nginx',
  'precheck',
  'dns_propagation_timeout',
  'notify',
  'certs',
];
const CERT_KEYS = ['names', 'exclude', 'challenge', 'dns', 'key_type', 'deploy'];
// Written into nginx files, so no characters that nginx treats specially.
const SAFE_PATH = /^\/[^\s;{}"'$#\\]*$/;

/** Paths zetcert writes into nginx files: absolute, without characters nginx treats specially. */
export function isSafePath(p: string): boolean {
  return SAFE_PATH.test(p);
}
const TLS_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const CIPHERS = /^[A-Za-z0-9:+!@=_.-]+$/;
const SESSION_CACHE = /^(off|none|builtin(:\d+)?|shared:[A-Za-z0-9_]+:\d+[kKmM]?)$/;
// Numbers with units, e.g. 1d, 4h, 1h30m, or plain seconds; one unit per number (no backtracking).
const NGINX_TIME = /^(?:\d+(?:ms|[smhdwMy]))*\d*$/;
const HTTP_ADDRESS = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:(\d{1,5}))?$/;

class Checker {
  constructor(
    private readonly file: string,
    private readonly doc: Document,
    private readonly lines: LineCounter,
  ) {}

  fail(keys: KeyPath, message: string): never {
    const node = this.doc.getIn(keys, true) as { range?: [number, number, number] } | undefined;
    const line = node?.range ? `:${this.lines.linePos(node.range[0]).line}` : '';
    throw new UserError(`${this.file}${line}: ${keys.join('.')}: ${message}`);
  }

  map(keys: KeyPath, value: unknown, allowed: string[]): Record<string, unknown> {
    if (value === null || value === undefined) return {};
    if (typeof value !== 'object' || Array.isArray(value)) this.fail(keys, 'must be a map');
    const map = value as Record<string, unknown>;
    for (const key of Object.keys(map)) {
      if (!allowed.includes(key)) this.fail([...keys, key], `unknown key (allowed: ${allowed.join(', ')})`);
    }
    return map;
  }

  string(keys: KeyPath, value: unknown): string {
    if (typeof value === 'number') return String(value);
    if (typeof value !== 'string') this.fail(keys, 'must be a string');
    return value;
  }

  list(keys: KeyPath, value: unknown): string[] {
    if (value === null || value === undefined) return [];
    const items = Array.isArray(value) ? value : [value];
    return items.map((item, i) => this.string(Array.isArray(value) ? [...keys, i] : keys, item));
  }

  oneOf<T extends string>(keys: KeyPath, value: unknown, allowed: readonly T[]): T {
    if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
      this.fail(keys, `must be ${allowed.join(', ').replace(/, ([^,]*)$/, ' or $1')}`);
    }
    return value as T;
  }

  onOff(keys: KeyPath, value: unknown): string {
    if (value === true || value === 'on') return 'on';
    if (value === false || value === 'off') return 'off';
    this.fail(keys, 'must be on or off');
  }

  path(keys: KeyPath, value: unknown): string {
    const p = this.string(keys, value);
    if (!SAFE_PATH.test(p)) this.fail(keys, 'must be an absolute path without spaces, quotes, ; { } $ # or \\');
    // certbot saves paths without a trailing slash; a different spelling would never match.
    const normalized = path.normalize(p);
    return normalized.length > 1 ? normalized.replace(/\/+$/, '') : normalized;
  }

  command(keys: KeyPath, value: unknown): string {
    const c = this.string(keys, value).trim();
    if (c === '') this.fail(keys, 'must not be empty');
    return c;
  }

  certName(keys: KeyPath, value: unknown): string {
    const name = this.string(keys, value);
    const normalized = normalizeCertName(name);
    if (!normalized) this.fail(keys, `not a valid DNS name: ${name}`);
    return normalized;
  }
}

function checkTls(c: Checker, value: unknown): TlsOverrides | 'off' {
  if (value === 'off' || value === false) return 'off';
  const map = c.map(['tls'], value, [...TLS_KEYS]);
  const tls: TlsOverrides = {};
  for (const [key, v] of Object.entries(map)) {
    const keys = ['tls', key];
    switch (key as TlsKey) {
      case 'protocols': {
        const protocols = c.list(keys, v).flatMap((p) => p.split(/\s+/)).filter(Boolean);
        for (const p of protocols) {
          if (!TLS_PROTOCOLS.includes(p)) c.fail(keys, `unknown protocol ${p} (allowed: ${TLS_PROTOCOLS.join(', ')})`);
        }
        if (protocols.length === 0) c.fail(keys, 'must name at least one protocol');
        tls.protocols = protocols.join(' ');
        break;
      }
      case 'ciphers':
        tls.ciphers = c.string(keys, v);
        if (!CIPHERS.test(tls.ciphers)) c.fail(keys, 'must be an OpenSSL cipher list such as ECDHE-ECDSA-AES128-GCM-SHA256:…');
        break;
      case 'prefer_server_ciphers':
      case 'session_tickets':
        tls[key as TlsKey] = c.onOff(keys, v);
        break;
      case 'session_cache': {
        const parts = c.string(keys, v).trim().split(/\s+/);
        if (!parts.every((p) => SESSION_CACHE.test(p))) {
          c.fail(keys, 'must be off, none, builtin[:size] or shared:<name>:<size>, e.g. shared:zetcert:10m');
        }
        tls.session_cache = parts.join(' ');
        break;
      }
      case 'session_timeout':
        tls.session_timeout = c.string(keys, v);
        if (tls.session_timeout === '' || !NGINX_TIME.test(tls.session_timeout)) {
          c.fail(keys, 'must be an nginx time such as 1d, 4h or 30m');
        }
        break;
      case 'dhparam':
        tls.dhparam = v === 'ffdhe2048' || v === 'off' || v === false ? (v === false ? 'off' : v) : c.path(keys, v);
        break;
    }
  }
  return tls;
}

function checkDuration(c: Checker, keys: KeyPath, value: unknown): number {
  if (typeof value === 'number' && value > 0) return value;
  const match = typeof value === 'string' ? /^(\d+)\s*(s|m|h)?$/.exec(value.trim()) : null;
  if (!match || Number(match[1]) === 0) c.fail(keys, 'must be a duration such as 180s or 3m');
  return Number(match[1]) * ({ s: 1, m: 60, h: 3600 }[match[2] ?? 's'] ?? 1);
}

function checkCert(c: Checker, name: string, value: unknown): CertConfig {
  const keys = ['certs', name];
  if (!isValidName(name)) c.fail(keys, `invalid certificate name: ${NAME_RULE}`);
  const map = c.map(keys, value, CERT_KEYS);
  const cert = defaultCertConfig();
  cert.names = c.list([...keys, 'names'], map.names).map((n, i) => c.certName([...keys, 'names', i], n));
  cert.exclude = c.list([...keys, 'exclude'], map.exclude).map((n, i) => c.certName([...keys, 'exclude', i], n));
  if (map.challenge !== undefined && map.challenge !== null) {
    cert.challenge = c.oneOf([...keys, 'challenge'], map.challenge, CHALLENGES);
  }
  if (map.dns !== undefined && map.dns !== null) {
    cert.dns = c.string([...keys, 'dns'], map.dns);
    if (!isValidName(cert.dns)) c.fail([...keys, 'dns'], `invalid DNS account name: ${NAME_RULE}`);
  }
  if (map.key_type !== undefined && map.key_type !== null) {
    cert.key_type = c.oneOf([...keys, 'key_type'], map.key_type, KEY_TYPES);
  }
  cert.deploy = c.list([...keys, 'deploy'], map.deploy).map((d, i) => c.command([...keys, 'deploy', i], d));

  const domain = wildcardDomain(name);
  if (domain !== undefined) {
    if (normalizeCertName(domain) !== domain) c.fail(keys, `wildcard.<domain>: ${domain} is not a valid domain`);
    if (cert.challenge === 'http') {
      c.fail([...keys, 'challenge'], 'a wildcard certificate is validated through DNS: challenge can only be auto or dns');
    }
    for (const [i, n] of cert.exclude.entries()) {
      if (n === domain || n === `*.${domain}`) {
        c.fail([...keys, 'exclude', i], `${name} always contains ${domain} and *.${domain}`);
      }
    }
  } else if (cert.challenge === 'http') {
    const wildcard = cert.names.find(isWildcard);
    if (wildcard) c.fail([...keys, 'challenge'], `http can't validate the wildcard name ${wildcard}: use auto or dns`);
  }
  return cert;
}

export function parseConfig(text: string, file: string): LoadedConfig {
  const lines = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lines, prettyErrors: false });
  const error = doc.errors[0];
  if (error) {
    const line = lines.linePos(error.pos[0]).line;
    throw new UserError(`${file}:${line}: ${error.message.split('\n')[0]}`);
  }
  const c = new Checker(file, doc, lines);
  const raw = c.map([], doc.toJS(), TOP_KEYS);
  const config = defaultConfig();

  if (raw.email !== undefined && raw.email !== null && raw.email !== '') {
    config.email = c.string(['email'], raw.email).trim();
    if (!/^[^\s@]+@[^\s@]+$/.test(config.email)) c.fail(['email'], 'must be an email address');
  }
  if (raw.webroot !== undefined) config.webroot = c.path(['webroot'], raw.webroot);
  config.public_ips = c.list(['public_ips'], raw.public_ips).map((ip, i) => {
    if (isIP(ip) === 0) c.fail(['public_ips', i], `not an IP address: ${ip}`);
    return ip;
  });
  if (raw.key_type !== undefined) config.key_type = c.oneOf(['key_type'], raw.key_type, KEY_TYPES);
  if (raw.tls !== undefined) config.tls = checkTls(c, raw.tls);

  const nginx = c.map(['nginx'], raw.nginx, ['config', 'test', 'reload']);
  if (nginx.config !== undefined) config.nginx.config = c.path(['nginx', 'config'], nginx.config);
  if (nginx.test !== undefined) config.nginx.test = c.command(['nginx', 'test'], nginx.test);
  if (nginx.reload !== undefined) config.nginx.reload = c.command(['nginx', 'reload'], nginx.reload);

  const precheck = c.map(['precheck'], raw.precheck, ['http_address']);
  if (precheck.http_address !== undefined) {
    const address = c.string(['precheck', 'http_address'], precheck.http_address);
    const match = HTTP_ADDRESS.exec(address);
    const port = match?.[3] === undefined ? 80 : Number(match[3]);
    if (!match || port < 1 || port > 65535) c.fail(['precheck', 'http_address'], 'must be host:port, e.g. 127.0.0.1:80');
    config.precheck.http_address = address;
  }

  if (raw.dns_propagation_timeout !== undefined) {
    config.dns_propagation_timeout = checkDuration(c, ['dns_propagation_timeout'], raw.dns_propagation_timeout);
  }
  if (raw.notify !== undefined && raw.notify !== null) config.notify = c.string(['notify'], raw.notify).trim();

  const certs = c.map(['certs'], raw.certs, Object.keys((raw.certs as object | null) ?? {}));
  for (const [name, value] of Object.entries(certs)) config.certs[name] = checkCert(c, name, value);

  return { path: file, exists: true, config, doc };
}

/** Loads the config; without a file (before `init`), every value is the default. */
export function loadConfig(file: string): LoadedConfig {
  const text = readText(file);
  if (text === undefined) {
    return { path: file, exists: false, config: defaultConfig(), doc: parseDocument('') };
  }
  return parseConfig(text, file);
}

/** The certificate's options from the config, or the defaults when it has none. */
export function certConfig(config: Config, cert: string): CertConfig {
  return config.certs[cert] ?? defaultCertConfig();
}
