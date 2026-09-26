// DNS accounts: /etc/zetcert/dns/<account>.yml, one per file, root-only (0600).
import { parseDocument, stringify } from 'yaml';
import { UserError } from '../system/errors';
import { listDir, readText, removeFile, writeFileAtomic } from '../system/fs';
import { DNS_DIR } from '../system/paths';
import { isValidName } from './names';

export const DRIVERS = ['cloudflare', 'route53'] as const;
/** challtestsrv exists only in the end-to-end test build. */
export type DriverName = (typeof DRIVERS)[number] | 'challtestsrv';

export interface DnsAccount {
  name: string;
  driver: DriverName;
  /** cloudflare: the API token. */
  token?: string;
  /** route53: both keys, or neither for the AWS default chain (environment, instance role). */
  access_key_id?: string;
  secret_access_key?: string;
  /** challtestsrv (test build only): its management URL, DNS address and zones. */
  url?: string;
  dns?: string;
  zones?: string[];
}

export function dnsAccountFile(name: string): string {
  return `${DNS_DIR}/${name}.yml`;
}

function optionalString(file: string, raw: Record<string, unknown>, key: string): string | undefined {
  const value = raw[key];
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new UserError(`${file}: ${key} must be a string`);
  return value;
}

export function parseDnsAccount(name: string, text: string, file = dnsAccountFile(name)): DnsAccount {
  const doc = parseDocument(text);
  if (doc.errors[0]) throw new UserError(`${file}: ${doc.errors[0].message.split('\n')[0]}`);
  const raw = (doc.toJS() ?? {}) as Record<string, unknown>;
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new UserError(`${file}: must be a map`);
  const driver = raw.driver;
  if (ZETCERT_E2E && driver === 'challtestsrv') {
    return {
      name,
      driver,
      url: String(raw.url ?? ''),
      dns: String(raw.dns ?? ''),
      zones: Array.isArray(raw.zones) ? raw.zones.map(String) : [],
    };
  }
  if (typeof driver !== 'string' || !(DRIVERS as readonly string[]).includes(driver)) {
    throw new UserError(`${file}: driver must be ${DRIVERS.join(' or ')}`);
  }
  const account: DnsAccount = { name, driver: driver as DriverName };
  const allowed = driver === 'cloudflare' ? ['driver', 'token'] : ['driver', 'access_key_id', 'secret_access_key'];
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw new UserError(`${file}: unknown key ${key} for driver ${driver}`);
  }
  if (driver === 'cloudflare') {
    account.token = optionalString(file, raw, 'token');
    if (!account.token) throw new UserError(`${file}: token is missing`);
  } else {
    account.access_key_id = optionalString(file, raw, 'access_key_id');
    account.secret_access_key = optionalString(file, raw, 'secret_access_key');
    if (!account.access_key_id !== !account.secret_access_key) {
      throw new UserError(`${file}: set both access_key_id and secret_access_key, or neither for the AWS default chain`);
    }
  }
  return account;
}

export function loadDnsAccount(name: string): DnsAccount | undefined {
  const text = readText(dnsAccountFile(name));
  return text === undefined ? undefined : parseDnsAccount(name, text);
}

/** The account names that have a file in /etc/zetcert/dns. */
export function dnsAccountNames(): string[] {
  return listDir(DNS_DIR)
    .filter((file) => file.endsWith('.yml') && isValidName(file.slice(0, -4)))
    .map((file) => file.slice(0, -4));
}

/** Every account in /etc/zetcert/dns, by name; a file that can't be read is an error. */
export function loadDnsAccounts(): DnsAccount[] {
  return dnsAccountNames()
    .map((name) => loadDnsAccount(name))
    .filter((account): account is DnsAccount => account !== undefined);
}

/** Every account that can be read, and the problems of those that can't: one broken file mustn't stop the others. */
export function loadDnsAccountsSafe(): { accounts: DnsAccount[]; problems: string[] } {
  const accounts: DnsAccount[] = [];
  const problems: string[] = [];
  for (const name of dnsAccountNames()) {
    try {
      const account = loadDnsAccount(name);
      if (account) accounts.push(account);
    } catch (err) {
      problems.push((err as Error).message);
    }
  }
  return { accounts, problems };
}

/** Writes the account file, root-only (0600): it holds credentials. */
export function saveDnsAccount(account: DnsAccount): void {
  const { name, ...fields } = account;
  const data = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined));
  writeFileAtomic(dnsAccountFile(name), stringify(data), 0o600);
}

export function removeDnsAccount(name: string): void {
  removeFile(dnsAccountFile(name));
}
