// Zone lookup: for each name, the account whose public zones contain it (longest match across
// all accounts), unless the certificate pins an account. Zones are cached in the state.
import type { DnsAccount } from '../config/dns-accounts';
import type { State } from '../system/state';
import type { DnsDriver, Zone } from './driver';

export interface ZoneMatch {
  account: DnsAccount;
  zone: Zone;
}

const CACHE_MS = 24 * 3600_000;

/** Whether `name` (without `*.`) is in `zone`. */
export function inZone(name: string, zone: string): boolean {
  const n = name.replace(/^\*\./, '');
  return n === zone || n.endsWith(`.${zone}`);
}

export class ZoneFinder {
  /** Accounts whose zones were fetched in this run. */
  private readonly fresh = new Set<string>();
  /** Accounts whose zones couldn't be listed; their cached zones are used when there are any. */
  readonly failures = new Map<string, string>();

  constructor(
    private readonly accounts: DnsAccount[],
    private readonly state: State,
    private readonly driverFor: (account: DnsAccount) => DnsDriver,
    private readonly now = new Date(),
  ) {}

  /**
   * The account's zones: cached, or fetched when the cache is old or `refresh` is set. When the
   * listing fails, the cached zones (or none) are used and the failure is kept in `failures`.
   */
  async zonesOf(account: DnsAccount, refresh = false): Promise<Zone[]> {
    const cached = this.state.zones[account.name];
    const old = !cached || this.now.getTime() - Date.parse(cached.at) > CACHE_MS;
    // Each account is fetched at most once per run.
    if (cached && (this.fresh.has(account.name) || (!old && !refresh))) return cached.zones;
    if (this.failures.has(account.name)) return cached?.zones ?? [];
    try {
      const zones = await this.driverFor(account).zones();
      this.state.zones[account.name] = { zones, at: this.now.toISOString() };
      this.fresh.add(account.name);
      return zones;
    } catch (err) {
      // One broken account mustn't break the others: go on with what is known about it.
      this.failures.set(account.name, (err as Error).message);
      return cached?.zones ?? [];
    }
  }

  private async best(name: string, candidates: DnsAccount[], refresh: boolean): Promise<ZoneMatch | undefined> {
    let best: ZoneMatch | undefined;
    for (const account of candidates) {
      for (const zone of await this.zonesOf(account, refresh)) {
        if (inZone(name, zone.name) && (!best || zone.name.length > best.zone.name.length)) best = { account, zone };
      }
    }
    return best;
  }

  /**
   * The account and zone for a name. With `pinned`, only that account counts. Zones are fetched
   * again once when no cached zone matches.
   */
  async find(name: string, pinned?: string): Promise<ZoneMatch | undefined> {
    const candidates = pinned ? this.accounts.filter((a) => a.name === pinned) : this.accounts;
    return (await this.best(name, candidates, false)) ?? (await this.best(name, candidates, true));
  }
}

/** The failures of a lookup as one line each, for messages. */
export function describeFailures(finder: ZoneFinder): string[] {
  return [...finder.failures].map(([account, error]) => `the zones of the DNS account ${account} can't be listed: ${error}`);
}
