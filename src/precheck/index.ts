// Runs the pre-checks on the names a certificate would be issued for.
import type { Validation } from '../certs/model';
import { checkAddresses, checkCaa, checkHttp, type CheckResult } from './checks';
import type { Lookup } from './lookup';

export interface NameCheck extends CheckResult {
  name: string;
}

export interface PrecheckContext {
  webroot: string;
  httpAddress: string;
  /** The config's public_ips and the public addresses found on this machine. */
  publicIps: string[];
  /** The ACME account URIs certbot may use, for CAA accounturi. */
  accountUris: string[];
  lookup: Lookup;
  /** DNS-validated names: an account manages the zone; added with the DNS drivers. */
  dnsZone?: (name: string) => Promise<CheckResult>;
}

async function checkName(name: string, validation: Validation, ctx: PrecheckContext): Promise<NameCheck> {
  const warnings: string[] = [];
  const steps: (() => Promise<CheckResult>)[] =
    validation === 'http'
      ? [
          () => checkAddresses(name, ctx.publicIps, ctx.lookup),
          () => checkHttp(name, ctx.webroot, ctx.httpAddress),
          () => checkCaa(name, 'http-01', ctx.accountUris, ctx.lookup),
        ]
      : [...(ctx.dnsZone ? [() => (ctx.dnsZone as (n: string) => Promise<CheckResult>)(name)] : []), () => checkCaa(name, 'dns-01', ctx.accountUris, ctx.lookup)];
  for (const step of steps) {
    const r = await step();
    warnings.push(...r.warnings);
    if (!r.ok) return { name, ok: false, reason: r.reason, warnings };
  }
  return { name, ok: true, warnings };
}

export async function precheckNames(names: string[], validation: Validation, ctx: PrecheckContext, concurrency = 8): Promise<NameCheck[]> {
  const results: NameCheck[] = new Array(names.length);
  let next = 0;
  const worker = async () => {
    while (next < names.length) {
      const i = next++;
      results[i] = await checkName(names[i] as string, validation, ctx);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, names.length) }, worker));
  return results;
}
