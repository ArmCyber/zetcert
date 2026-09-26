// Propagation: after creating a record, query the zone's authoritative nameservers until the
// value shows on all of them, instead of sleeping a fixed time.
import { promises as dns } from 'node:dns';

export interface Nameserver {
  name: string;
  addresses: string[];
}

export interface PropagationDeps {
  nameservers(zone: string): Promise<Nameserver[]>;
  /** TXT records at `name` as one server answers them; each record is a list of strings. */
  txt(server: string, name: string): Promise<string[][]>;
  sleep(ms: number): Promise<void>;
  now(): number;
}

export async function authoritativeNameservers(zone: string): Promise<Nameserver[]> {
  const resolver = new dns.Resolver({ timeout: 5000, tries: 2 });
  const names = await resolver.resolveNs(zone);
  const result: Nameserver[] = [];
  for (const name of names) {
    const v4 = await resolver.resolve4(name).catch(() => [] as string[]);
    const v6 = await resolver.resolve6(name).catch(() => [] as string[]);
    result.push({ name, addresses: [...v4, ...v6] });
  }
  return result;
}

export const systemDeps: PropagationDeps = {
  nameservers: authoritativeNameservers,
  async txt(server, name) {
    const resolver = new dns.Resolver({ timeout: 3000, tries: 1 });
    resolver.setServers([server]);
    try {
      return await resolver.resolveTxt(name);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENODATA' || code === 'ENOTFOUND') return [];
      throw err;
    }
  },
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => Date.now(),
};

let fakeDeps: PropagationDeps | undefined;

/** Replaces the DNS queries of the propagation check. Tests only. */
export function setPropagationDeps(deps: PropagationDeps | undefined): void {
  fakeDeps = deps;
}

export interface WaitOptions {
  timeoutMs: number;
  pollMs?: number;
  /** Nameservers to ask instead of the zone's NS records (the test build asks challtestsrv). */
  servers?: Nameserver[];
  deps?: PropagationDeps;
}

/** Waits until `value` is in the TXT records at `name` on every authoritative nameserver of `zone`. */
export async function waitForTxt(name: string, value: string, zone: string, options: WaitOptions): Promise<void> {
  const deps = options.deps ?? fakeDeps ?? systemDeps;
  const servers = options.servers ?? (await deps.nameservers(zone));
  if (servers.length === 0) throw new Error(`no nameservers found for ${zone}`);
  const deadline = deps.now() + options.timeoutMs;
  const pending = new Map(servers.map((s) => [s.name, s]));
  const visible = async (ns: Nameserver) => {
    for (const address of ns.addresses) {
      try {
        const records = await deps.txt(address, name);
        return records.some((chunks) => chunks.join('') === value);
      } catch {
        // this address doesn't answer: try the next one
      }
    }
    return false;
  };
  for (;;) {
    for (const ns of [...pending.values()]) {
      if (await visible(ns)) pending.delete(ns.name);
    }
    if (pending.size === 0) return;
    const left = deadline - deps.now();
    if (left <= 0) {
      throw new Error(
        `the TXT record ${name} isn't visible on ${[...pending.keys()].join(', ')} after ${Math.round(options.timeoutMs / 1000)}s (dns_propagation_timeout)`,
      );
    }
    await deps.sleep(Math.min(options.pollMs ?? 5000, left));
  }
}
