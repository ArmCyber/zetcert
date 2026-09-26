import { describe, expect, it } from 'vitest';
import { type PropagationDeps, waitForTxt } from '../../../src/dns/propagation';

/** Two nameservers; ns2 gets the record after `delayMs`; ns1's IPv6 address never answers. */
function deps(delayMs: number, value = 'token') {
  let clock = 0;
  const queries: string[] = [];
  const d: PropagationDeps = {
    nameservers: async () => [
      { name: 'ns1.example.net', addresses: ['2001:db8::1', '192.0.2.1'] },
      { name: 'ns2.example.net', addresses: ['192.0.2.2'] },
    ],
    txt: async (server, name) => {
      queries.push(`${server} ${name}`);
      if (server === '2001:db8::1') throw new Error('ETIMEOUT');
      if (server === '192.0.2.2' && clock < delayMs) return [['other']];
      return [['other'], [value.slice(0, 3), value.slice(3)]];
    },
    sleep: async (ms) => void (clock += ms),
    now: () => clock,
  };
  return { d, queries, clock: () => clock };
}

describe('propagation', () => {
  it('waits until every authoritative nameserver has the value', async () => {
    const { d, clock } = deps(12_000);
    await waitForTxt('_acme-challenge.client.example', 'token', 'client.example', { timeoutMs: 180_000, pollMs: 5000, deps: d });
    expect(clock()).toBe(15_000);
  });

  it('counts a nameserver when one of its addresses answers', async () => {
    const { d, queries } = deps(0);
    await waitForTxt('_acme-challenge.client.example', 'token', 'client.example', { timeoutMs: 1000, deps: d });
    expect(queries.slice(0, 2)).toEqual(['2001:db8::1 _acme-challenge.client.example', '192.0.2.1 _acme-challenge.client.example']);
  });

  it('gives up after the timeout, naming the nameservers without the value', async () => {
    const { d } = deps(Infinity);
    await expect(
      waitForTxt('_acme-challenge.client.example', 'token', 'client.example', { timeoutMs: 20_000, pollMs: 5000, deps: d }),
    ).rejects.toThrow("the TXT record _acme-challenge.client.example isn't visible on ns2.example.net after 20s (dns_propagation_timeout)");
  });

  it('asks the given servers instead of the NS records', async () => {
    const { d, queries } = deps(0);
    await waitForTxt('_acme-challenge.a.test', 'token', 'test', { timeoutMs: 1000, deps: d, servers: [{ name: 'challtestsrv', addresses: ['192.0.2.1'] }] });
    expect(queries).toEqual(['192.0.2.1 _acme-challenge.a.test']);
  });
});
