// DNS lookups for the pre-checks, replaceable in tests.
import { promises as dns } from 'node:dns';

export interface CaaEntry {
  critical: number;
  tag: string;
  value: string;
}

export interface Lookup {
  /** Addresses; empty when the name has none. */
  addresses(name: string, family: 4 | 6): Promise<string[]>;
  /** The CAA records at exactly this name; empty when there are none. */
  caa(name: string): Promise<CaaEntry[]>;
}

/**
 * A record from dns.resolveCaa: `{ critical, issue: 'letsencrypt.org' }`, and on newer Node also
 * `type: 'CAA'`.
 */
export function caaEntry(record: Record<string, unknown>): CaaEntry {
  const [tag = '', value = ''] = Object.entries(record).find(([key]) => key !== 'critical' && key !== 'type') ?? [];
  return { critical: Number(record.critical) || 0, tag: tag.toLowerCase(), value: String(value) };
}

const EMPTY = new Set(['ENODATA', 'ENOTFOUND', 'NXDOMAIN']);

function emptyWhenMissing<T>(err: unknown): T[] {
  if (EMPTY.has((err as NodeJS.ErrnoException).code ?? '')) return [];
  throw err;
}

let fake: Lookup | undefined;

/** Replaces DNS lookups. Tests only; `undefined` restores the system resolver. */
export function setLookup(lookup: Lookup | undefined): void {
  fake = lookup;
}

export function systemLookup(): Lookup {
  if (fake) return fake;
  const resolver = new dns.Resolver({ timeout: 5000, tries: 2 });
  return {
    async addresses(name, family) {
      try {
        return family === 4 ? await resolver.resolve4(name) : await resolver.resolve6(name);
      } catch (err) {
        return emptyWhenMissing(err);
      }
    },
    async caa(name) {
      try {
        return (await resolver.resolveCaa(name)).map((r) => caaEntry(r as unknown as Record<string, unknown>));
      } catch (err) {
        return emptyWhenMissing(err);
      }
    },
  };
}
