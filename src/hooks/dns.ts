// certbot's manual hooks for DNS validation:
//   --manual-auth-hook    "/usr/local/sbin/zetcert hook auth --cert <cert>"
//   --manual-cleanup-hook "/usr/local/sbin/zetcert hook cleanup --cert <cert>"
// certbot passes the auth hook's stdout to the cleanup hook as CERTBOT_AUTH_OUTPUT, so stdout
// carries only the record reference; everything else goes to stderr.
import type { Context } from '../cli/program';
import { certConfig, loadConfig } from '../config/config';
import { loadDnsAccount, loadDnsAccountsSafe } from '../config/dns-accounts';
import type { RecordRef, Zone } from '../dns/driver';
import { driverFor, propagationServers } from '../dns/index';
import { waitForTxt } from '../dns/propagation';
import { describeFailures, ZoneFinder } from '../dns/zones';
import { loadState, saveState } from '../system/state';

interface AuthOutput {
  account: string;
  zone: Zone;
  record: RecordRef;
}

function log(ctx: Context, message: string): void {
  ctx.out.stderr.write(`zetcert: ${message}\n`);
}

function identifier(env: NodeJS.ProcessEnv): string {
  // For a wildcard the identifier is the base domain.
  return (env.CERTBOT_IDENTIFIER || env.CERTBOT_DOMAIN || '').replace(/^\*\./, '').toLowerCase();
}

export async function authHook(ctx: Context, cert: string, env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const name = identifier(env);
  const value = env.CERTBOT_VALIDATION ?? '';
  if (!name || !value) {
    log(ctx, 'CERTBOT_IDENTIFIER (or CERTBOT_DOMAIN) and CERTBOT_VALIDATION must be set: certbot runs this hook');
    return 1;
  }
  try {
    const config = loadConfig(ctx.configPath).config;
    const pinned = certConfig(config, cert).dns;
    const state = loadState();
    const { accounts, problems } = loadDnsAccountsSafe();
    for (const problem of problems) log(ctx, `warning: ${problem}`);
    const finder = new ZoneFinder(accounts, state, driverFor);
    const match = await finder.find(name, pinned);
    saveState(state);
    for (const failure of describeFailures(finder)) log(ctx, `warning: ${failure}`);
    if (!match) {
      log(ctx, pinned ? `the DNS account ${pinned} has no zone for ${name}` : `no DNS account manages ${name}: run zetcert dns add …`);
      return 1;
    }
    const record = `_acme-challenge.${name}`;
    const ref = await driverFor(match.account).createTxt(match.zone, record, value);
    const output: AuthOutput = { account: match.account.name, zone: match.zone, record: ref };
    ctx.out.stdout.write(`${JSON.stringify(output)}\n`);
    log(ctx, `created the TXT record ${record} with ${match.account.name}; waiting until the nameservers of ${match.zone.name} have it…`);
    await waitForTxt(record, value, match.zone.name, {
      timeoutMs: config.dns_propagation_timeout * 1000,
      servers: propagationServers(match.account),
    });
    log(ctx, `${record} is visible on every authoritative nameserver of ${match.zone.name}`);
    return 0;
  } catch (err) {
    // certbot ignores this exit code and answers the challenge anyway; this explains the failure.
    log(ctx, `${cert}: ${(err as Error).message}`);
    return 1;
  }
}

function parseAuthOutput(text: string | undefined): AuthOutput | undefined {
  try {
    const parsed = JSON.parse((text ?? '').trim().split('\n').pop() ?? '') as Partial<AuthOutput>;
    if (typeof parsed.account === 'string' && parsed.zone?.id && parsed.record?.name) return parsed as AuthOutput;
  } catch {
    // empty or not ours: fall back to the identifier
  }
  return undefined;
}

export async function cleanupHook(ctx: Context, cert: string, env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const name = identifier(env);
  try {
    const saved = parseAuthOutput(env.CERTBOT_AUTH_OUTPUT);
    if (saved) {
      const account = loadDnsAccount(saved.account);
      if (!account) throw new Error(`the DNS account ${saved.account} no longer exists`);
      await driverFor(account).deleteTxt(saved.zone, saved.record);
      log(ctx, `deleted the TXT record ${saved.record.name}`);
      return 0;
    }
    // The auth hook failed before printing: find the record by identifier and value.
    const config = loadConfig(ctx.configPath).config;
    const state = loadState();
    const match = await new ZoneFinder(loadDnsAccountsSafe().accounts, state, driverFor).find(name, certConfig(config, cert).dns);
    if (!match) throw new Error(`no DNS account manages ${name}`);
    const record = `_acme-challenge.${name}`;
    await driverFor(match.account).deleteTxt(match.zone, { name: record, value: env.CERTBOT_VALIDATION ?? '' });
    log(ctx, `deleted the TXT record ${record}`);
  } catch (err) {
    log(ctx, `warning: couldn't delete the TXT record for ${name || cert}: ${(err as Error).message}`);
  }
  return 0;
}
