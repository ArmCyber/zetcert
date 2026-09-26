import { describe, expect, it } from 'vitest';
import type { DnsAccount } from '../../../src/config/dns-accounts';
import type { DnsDriver, Zone } from '../../../src/dns/driver';
import { inZone, ZoneFinder } from '../../../src/dns/zones';
import { emptyState } from '../../../src/system/state';

const accounts: DnsAccount[] = [
  { name: 'aws', driver: 'route53' },
  { name: 'cf-main', driver: 'cloudflare', token: 't' },
];

function drivers(zones: Record<string, string[]>) {
  const calls: string[] = [];
  const driverFor = (account: DnsAccount): DnsDriver => ({
    verify: async () => {},
    zones: async () => {
      calls.push(account.name);
      return (zones[account.name] ?? []).map((name, i): Zone => ({ id: `${account.name}-${i}`, name }));
    },
    createTxt: async () => ({ name: '', value: '' }),
    deleteTxt: async () => {},
  });
  return { calls, driverFor };
}

describe('zone lookup', () => {
  it('matches names and wildcards', () => {
    expect(inZone('client.example', 'client.example')).toBe(true);
    expect(inZone('*.eu.client.example', 'client.example')).toBe(true);
    expect(inZone('_acme-challenge.a.client.example', 'client.example')).toBe(true);
    expect(inZone('otherclient.example', 'client.example')).toBe(false);
  });

  it('takes the longest matching zone across all accounts', async () => {
    const { driverFor } = drivers({ aws: ['client.example'], 'cf-main': ['eu.client.example', 'example.org'] });
    const finder = new ZoneFinder(accounts, emptyState(), driverFor);
    expect((await finder.find('api.eu.client.example'))?.account.name).toBe('cf-main');
    expect((await finder.find('*.client.example'))?.account.name).toBe('aws');
    expect(await finder.find('nowhere.invalid')).toBeUndefined();
  });

  it('uses only the pinned account', async () => {
    const { driverFor } = drivers({ aws: ['client.example'], 'cf-main': ['eu.client.example'] });
    const finder = new ZoneFinder(accounts, emptyState(), driverFor);
    expect((await finder.find('api.eu.client.example', 'aws'))?.zone.name).toBe('client.example');
    expect(await finder.find('example.org', 'aws')).toBeUndefined();
  });

  it("goes on without an account whose zones can't be listed: its cached zones, or none", async () => {
    const state = emptyState();
    state.zones.aws = { zones: [{ id: 'cached', name: 'client.example' }], at: '2026-09-01T00:00:00Z' };
    const calls: string[] = [];
    const driverFor = (account: DnsAccount): DnsDriver => ({
      verify: async () => {},
      zones: async () => {
        calls.push(account.name);
        if (account.name === 'aws' || account.name === 'broken') throw new Error('Invalid access token');
        return [{ id: 'z', name: 'example.org' }];
      },
      createTxt: async () => ({ name: '', value: '' }),
      deleteTxt: async () => {},
    });
    const finder = new ZoneFinder([...accounts, { name: 'broken', driver: 'cloudflare', token: 'x' }], state, driverFor, new Date('2026-09-26T00:00:00Z'));
    expect((await finder.find('a.client.example'))?.zone.id).toBe('cached');
    expect((await finder.find('www.example.org'))?.account.name).toBe('cf-main');
    expect([...finder.failures.keys()]).toEqual(['aws', 'broken']);
    expect(calls.filter((c) => c === 'aws')).toHaveLength(1);
  });

  it('uses the cache, and fetches again when a name has no cached zone or the cache is old', async () => {
    const state = emptyState();
    const now = new Date('2026-09-26T12:00:00Z');
    state.zones.aws = { zones: [{ id: 'old', name: 'client.example' }], at: '2026-09-26T11:00:00Z' };
    state.zones['cf-main'] = { zones: [], at: '2026-09-26T11:00:00Z' };
    const { calls, driverFor } = drivers({ aws: ['client.example', 'new.test'], 'cf-main': [] });
    const finder = new ZoneFinder(accounts, state, driverFor, now);
    expect((await finder.find('a.client.example'))?.zone.id).toBe('old');
    expect(calls).toEqual([]);
    expect((await finder.find('a.new.test'))?.zone.name).toBe('new.test');
    expect(calls).toEqual(['aws', 'cf-main']);
    expect(state.zones.aws?.zones.map((z) => z.name)).toEqual(['client.example', 'new.test']);

    state.zones.aws.at = '2026-09-20T00:00:00Z';
    const later = drivers({ aws: ['client.example'] });
    await new ZoneFinder(accounts, state, later.driverFor, now).find('a.client.example');
    expect(later.calls).toEqual(['aws']);
  });
});
