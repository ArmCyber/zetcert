// An in-memory DNS provider for tests: drivers per account, and the propagation check answering
// from the same records.
import type { DnsAccount } from '../../src/config/dns-accounts';
import type { DnsDriver, Zone } from '../../src/dns/driver';
import type { PropagationDeps } from '../../src/dns/propagation';

export class FakeDns {
  /** Zones per account name. */
  zones: Record<string, string[]> = {};
  /** TXT values per record name. */
  txt = new Map<string, string[]>();
  /** Accounts whose credentials fail. */
  broken = new Set<string>();
  log: string[] = [];

  driver = (account: DnsAccount): DnsDriver => ({
    verify: async () => {
      if (this.broken.has(account.name)) throw new Error('Invalid access token (9109)');
    },
    zones: async () => {
      if (this.broken.has(account.name)) throw new Error('Invalid access token (9109)');
      return (this.zones[account.name] ?? []).map((name): Zone => ({ id: `${account.name}:${name}`, name }));
    },
    createTxt: async (zone, name, value) => {
      this.log.push(`create ${account.name} ${zone.name} ${name} ${value}`);
      this.txt.set(name, [...(this.txt.get(name) ?? []), value]);
      return { name, value, id: `${name}/${value}` };
    },
    deleteTxt: async (zone, ref) => {
      this.log.push(`delete ${account.name} ${zone.name} ${ref.name} ${ref.value}`);
      this.txt.set(ref.name, (this.txt.get(ref.name) ?? []).filter((v) => v !== ref.value));
    },
  });

  propagation: PropagationDeps = {
    nameservers: async () => [{ name: 'ns1.fake', addresses: ['192.0.2.53'] }],
    txt: async (_server, name) => (this.txt.get(name) ?? []).map((v) => [v]),
    sleep: async () => {},
    now: () => 0,
  };
}
