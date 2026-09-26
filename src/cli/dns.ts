// `zetcert dns add|list|test|remove`: the DNS accounts used for DNS validation.
import { randomBytes } from 'node:crypto';
import { buildModel } from '../certs/model';
import { loadConfig } from '../config/config';
import {
  type DnsAccount,
  dnsAccountNames,
  DRIVERS,
  loadDnsAccount,
  loadDnsAccountsSafe,
  removeDnsAccount,
  saveDnsAccount,
} from '../config/dns-accounts';
import { isValidName, NAME_RULE } from '../config/names';
import type { Zone } from '../dns/driver';
import { driverFor, propagationServers } from '../dns/index';
import { waitForTxt } from '../dns/propagation';
import { ZoneFinder } from '../dns/zones';
import { discover } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { existingSnippets } from '../nginx/snippets';
import { UserError } from '../system/errors';
import { loadState, saveState } from '../system/state';
import type { Context } from './program';

export interface DnsAddOptions {
  driver: string;
  fromStdin?: boolean;
}

function requireAccount(name: string): DnsAccount {
  const account = loadDnsAccount(name);
  if (!account) throw new UserError(`no DNS account named ${name}: zetcert dns list shows them`);
  return account;
}

async function checked<T>(what: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    throw new UserError(`${what}: ${(err as Error).message}`);
  }
}

function cacheZones(account: string, zones: Zone[]): void {
  const state = loadState();
  state.zones[account] = { zones, at: new Date().toISOString() };
  saveState(state);
}

export async function dnsAdd(ctx: Context, name: string, options: DnsAddOptions): Promise<number> {
  const { out } = ctx;
  if (!isValidName(name)) throw new UserError(`invalid DNS account name: account names ${NAME_RULE}`);
  if (!(DRIVERS as readonly string[]).includes(options.driver)) throw new UserError(`--driver must be ${DRIVERS.join(' or ')}`);
  if (loadDnsAccount(name)) throw new UserError(`the DNS account ${name} exists: zetcert dns remove ${name} first`);

  if (!options.fromStdin && !ctx.prompt.interactive) {
    throw new UserError('no terminal to ask for the credentials: pass them on stdin with --from-stdin');
  }
  const lines = options.fromStdin ? (await ctx.readStdin()).split('\n').map((l) => l.trim()) : [];
  const account: DnsAccount = { name, driver: options.driver as DnsAccount['driver'] };
  if (options.driver === 'cloudflare') {
    account.token = options.fromStdin ? lines[0] : await ctx.prompt.secret('Cloudflare API token:');
    if (!account.token) throw new UserError('the Cloudflare API token is empty');
  } else {
    const keyId = options.fromStdin ? lines[0] : await ctx.prompt.ask('AWS access key id (empty for the AWS default chain):', '');
    if (keyId) {
      account.access_key_id = keyId;
      account.secret_access_key = options.fromStdin ? lines[1] : await ctx.prompt.secret('AWS secret access key:');
      if (!account.secret_access_key) throw new UserError('the AWS secret access key is empty');
    }
  }

  const driver = driverFor(account);
  await checked("the credentials don't work", () => driver.verify());
  const zones = await checked("the zones can't be listed", () => driver.zones());
  saveDnsAccount(account);
  cacheZones(name, zones);
  out.info(`Added the DNS account ${name} (${account.driver}).`);
  if (zones.length === 0) out.warn(`${name} can't edit any public zone`);
  else out.info(`Zones: ${zones.map((z) => z.name).join(', ')}`);
  return 0;
}

export async function dnsList(ctx: Context): Promise<number> {
  const { out } = ctx;
  const state = loadState();
  const rows: { name: string; driver: string; zones: string[]; error?: string }[] = [];
  for (const name of dnsAccountNames()) {
    let account: DnsAccount | undefined;
    try {
      account = loadDnsAccount(name);
    } catch (err) {
      rows.push({ name, driver: '?', zones: [], error: (err as Error).message });
      continue;
    }
    if (!account) continue;
    try {
      const zones = await driverFor(account).zones();
      state.zones[account.name] = { zones, at: new Date().toISOString() };
      rows.push({ name: account.name, driver: account.driver, zones: zones.map((z) => z.name) });
    } catch (err) {
      const cached = state.zones[account.name]?.zones.map((z) => z.name) ?? [];
      rows.push({ name: account.name, driver: account.driver, zones: cached, error: (err as Error).message });
    }
  }
  saveState(state);
  if (ctx.opts.json) {
    out.print(JSON.stringify({ accounts: rows.map((r) => ({ ...r, error: r.error ?? null })) }, null, 2));
  } else if (rows.length === 0) {
    out.info('No DNS accounts: zetcert dns add <account> --driver cloudflare|route53');
  } else {
    for (const line of out.table(['ACCOUNT', 'DRIVER', 'ZONES'], rows.map((r) => [r.name, r.driver, r.zones.join(', ') || '(none)']))) {
      out.info(line);
    }
  }
  for (const r of rows.filter((row) => row.error)) out.warn(`${r.name}: ${r.error}${r.driver === '?' ? '' : ' (showing the cached zones)'}`);
  return rows.some((r) => r.error) ? 1 : 0;
}

export async function dnsTest(ctx: Context, name: string, recordName: string | undefined): Promise<number> {
  const { out } = ctx;
  const account = requireAccount(name);
  const driver = driverFor(account);
  await checked("the credentials don't work", () => driver.verify());
  const zones = await checked("the zones can't be listed", () => driver.zones());
  cacheZones(name, zones);
  out.info(`${name}: the credentials work. Zones: ${zones.map((z) => z.name).join(', ') || '(none)'}`);
  if (!recordName) return 0;

  const base = recordName.replace(/^\*\./, '').toLowerCase();
  const zone = zones
    .filter((z) => base === z.name || base.endsWith(`.${z.name}`))
    .sort((a, b) => b.name.length - a.name.length)[0];
  if (!zone) throw new UserError(`${name} has no zone for ${recordName}`);
  const txt = `_acme-challenge.${base}`;
  const value = `zetcert-test-${randomBytes(8).toString('hex')}`;
  const ref = await checked(`creating a TXT record at ${txt} failed`, () => driver.createTxt(zone, txt, value));
  out.info(`Created a test TXT record at ${txt}; waiting until the nameservers of ${zone.name} have it…`);
  try {
    const config = loadConfig(ctx.configPath).config;
    await waitForTxt(txt, value, zone.name, { timeoutMs: config.dns_propagation_timeout * 1000, servers: propagationServers(account) });
    out.info('The record is visible on every authoritative nameserver.');
  } finally {
    await checked(`deleting the test record at ${txt} failed`, () => driver.deleteTxt(zone, ref));
    out.info('Deleted the test record.');
  }
  return 0;
}

export async function dnsRemove(ctx: Context, name: string): Promise<number> {
  let account: DnsAccount | undefined;
  let unreadable: string | undefined;
  try {
    account = loadDnsAccount(name);
  } catch (err) {
    // A file that can't be read serves no certificate; it can still be removed.
    unreadable = (err as Error).message;
  }
  if (!account && !unreadable) throw new UserError(`no DNS account named ${name}: zetcert dns list shows them`);
  const config = loadConfig(ctx.configPath).config;
  const users = new Set(Object.entries(config.certs).filter(([, c]) => c.dns === name).map(([cert]) => cert));
  const state = loadState();
  if (account) {
    let models;
    try {
      models = buildModel({ config, discovery: discover(loadNginxConfig(config.nginx.config)), snippets: existingSnippets() });
    } catch (err) {
      throw new UserError(`can't check which certificates use ${name}: ${(err as Error).message}`);
    }
    const finder = new ZoneFinder(loadDnsAccountsSafe().accounts, state, driverFor);
    for (const model of models.filter((m) => m.validation === 'dns' && !m.dnsAccount)) {
      for (const n of model.names) {
        if ((await finder.find(n.name))?.account.name === name) users.add(model.cert);
      }
    }
    // Without another account's zones, the longest match isn't known: refuse rather than guess.
    const others = [...finder.failures].filter(([other]) => other !== name);
    if (others.length > 0) {
      throw new UserError(
        `can't check which certificates use ${name}: ${others.map(([other, error]) => `the zones of ${other} can't be listed: ${error}`).join('; ')}`,
      );
    }
  }
  if (users.size > 0) {
    throw new UserError(`${name} is used by ${[...users].sort().join(', ')}: move ${users.size > 1 ? 'them' : 'it'} to another account first`);
  }
  removeDnsAccount(name);
  delete state.zones[name];
  saveState(state);
  ctx.out.info(`Removed the DNS account ${name}.`);
  return 0;
}
