import type { LookupAddress, Resolver } from 'node:dns';
import { existsSync, readFileSync, statSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { npmLatestVersion, startUpdateCheck, stoppableLookup } from '../../../src/system/update';
import { makeCert } from '../certs-helper';
import { tempRoot } from '../helpers';

const FILE = '/var/lib/zetcert/update.json';
const NOW = new Date('2026-10-12T10:00:00Z');
const HOUR = 3_600_000;

/** npm with `version` as its latest, or unreachable without one; counts how often it is asked. */
function npm(version?: string) {
  const registry = {
    asked: 0,
    latestVersion: async () => {
      registry.asked++;
      if (version === undefined) throw new Error('getaddrinfo ENOTFOUND registry.npmjs.org');
      return version;
    },
  };
  return registry;
}

/** npm that never answers; `signal()` is what the request was given to stop it. */
function silentNpm() {
  let signal: AbortSignal | undefined;
  return {
    signal: () => signal,
    latestVersion: (s: AbortSignal) => {
      signal = s;
      return new Promise<string>(() => {});
    },
  };
}

describe('the update check', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => {
    vi.useRealTimers();
    root.cleanup();
  });

  const saved = () => JSON.parse(readFileSync(root.path(FILE), 'utf8')) as unknown;

  it('asks npm, tells when its version is newer, and saves the answer', async () => {
    const registry = npm('0.2.0');
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer).toBe('0.2.0');
    expect(registry.asked).toBe(1);
    expect(saved()).toEqual({ checked: '2026-10-12T10:00:00.000Z', latest: '0.2.0' });
    expect(statSync(root.path(FILE)).mode & 0o777).toBe(0o644);
  });

  it.each([
    ['0.1.3', '0.1.4', '0.1.4'],
    ['0.1.3', '1.0.0', '1.0.0'],
    ['0.2.0-rc.1', '0.2.0', '0.2.0'],
    ['0.2.0', '0.2.0', undefined],
    ['0.2.1', '0.2.0', undefined],
    ['0.2.0', '0.2.0-rc.1', undefined],
  ])('running %s with %s on npm tells %s', async (running, latest, newer) => {
    expect(await startUpdateCheck(running, npm(latest).latestVersion, NOW).newer).toBe(newer);
  });

  it("doesn't ask again for a day, and still knows the answer", async () => {
    const registry = npm('0.2.0');
    await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer;
    const later = new Date(NOW.getTime() + 23 * HOUR);
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, later).newer).toBe('0.2.0');
    // After the upgrade, the saved answer is no longer news.
    expect(await startUpdateCheck('0.2.0', registry.latestVersion, later).newer).toBeUndefined();
    expect(registry.asked).toBe(1);
  });

  it('asks again after a day', async () => {
    await startUpdateCheck('0.1.3', npm('0.1.3').latestVersion, NOW).newer;
    const registry = npm('0.2.0');
    const nextDay = new Date(NOW.getTime() + 24 * HOUR);
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, nextDay).newer).toBe('0.2.0');
    expect(registry.asked).toBe(1);
    expect(saved()).toEqual({ checked: '2026-10-13T10:00:00.000Z', latest: '0.2.0' });
  });

  it('tells nothing while npm is unreachable, saves nothing, and asks again the next time', async () => {
    const registry = npm();
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer).toBeUndefined();
    expect(existsSync(root.path(FILE))).toBe(false);
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, new Date(NOW.getTime() + 1000)).newer).toBeUndefined();
    expect(registry.asked).toBe(2);
  });

  it('keeps its last answer while npm is unreachable', async () => {
    await startUpdateCheck('0.1.3', npm('0.2.0').latestVersion, NOW).newer;
    const registry = npm();
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, new Date(NOW.getTime() + 25 * HOUR)).newer).toBe('0.2.0');
    expect(registry.asked).toBe(1);
    // The time of npm's last answer stays, so the next run asks again.
    expect(saved()).toEqual({ checked: '2026-10-12T10:00:00.000Z', latest: '0.2.0' });
  });

  it.each(['latest', '', '1.2', 'v9.9.9', ' 9.9.9', '9.9.9\n', '9.9.9\x1b[31m'])('ignores the answer %j', async (answer) => {
    expect(await startUpdateCheck('0.1.3', npm(answer).latestVersion, NOW).newer).toBeUndefined();
    expect(existsSync(root.path(FILE))).toBe(false);
  });

  it.each([
    '{ not json',
    'null',
    '[]',
    '{"checked": "2026-10-12T09:00:00.000Z"}',
    '{"checked": "2026-10-12T09:00:00.000Z", "latest": "9.9.9\\u001b[31m"}',
    '{"checked": "yesterday", "latest": "9.9.9"}',
    // The clock was wrong when it was saved.
    '{"checked": "2026-10-12T11:00:00.000Z", "latest": "9.9.9"}',
  ])('counts the file %s as never asked', async (content) => {
    root.write(FILE, content);
    const registry = npm('0.1.3');
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer).toBeUndefined();
    expect(registry.asked).toBe(1);
    expect(saved()).toEqual({ checked: '2026-10-12T10:00:00.000Z', latest: '0.1.3' });
  });

  it("still tells when the answer can't be saved", async () => {
    root.write('/var/lib/zetcert', 'not a directory');
    const registry = npm('0.2.0');
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer).toBe('0.2.0');
    expect(await startUpdateCheck('0.1.3', registry.latestVersion, NOW).newer).toBe('0.2.0');
    expect(registry.asked).toBe(2);
  });

  it('gives npm 2 seconds, then stops the request', async () => {
    vi.useFakeTimers();
    const registry = silentNpm();
    const check = startUpdateCheck('0.1.3', registry.latestVersion, NOW);
    let done = false;
    void check.newer.then(() => (done = true));
    await vi.advanceTimersByTimeAsync(1999);
    expect(done).toBe(false);
    expect(registry.signal()?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toBe(true);
    expect(registry.signal()?.aborted).toBe(true);
    expect(await check.newer).toBeUndefined();
    expect(existsSync(root.path(FILE))).toBe(false);
  });

  it('leaves no timer behind', async () => {
    vi.useFakeTimers();
    await startUpdateCheck('0.1.3', npm('0.2.0').latestVersion, NOW).newer;
    expect(vi.getTimerCount()).toBe(0);
    await startUpdateCheck('0.1.3', npm().latestVersion, new Date(NOW.getTime() + 48 * HOUR)).newer;
    expect(vi.getTimerCount()).toBe(0);
    const cancelled = startUpdateCheck('0.1.3', silentNpm().latestVersion, new Date(NOW.getTime() + 48 * HOUR));
    cancelled.cancel();
    await cancelled.newer;
    expect(vi.getTimerCount()).toBe(0);
  });

  it('stops the request when cancelled, and falls back on its last answer', async () => {
    await startUpdateCheck('0.1.3', npm('0.2.0').latestVersion, NOW).newer;
    const registry = silentNpm();
    const check = startUpdateCheck('0.1.3', registry.latestVersion, new Date(NOW.getTime() + 48 * HOUR));
    expect(registry.signal()?.aborted).toBe(false);
    check.cancel();
    expect(registry.signal()?.aborted).toBe(true);
    expect(await check.newer).toBe('0.2.0');
  });
});

describe('asking npm', () => {
  // Its own issuer, so the request can trust it as a CA.
  const cert = makeCert({ names: ['npm.example'], issuer: 'npm.example' });
  const trusted = { ca: cert.pem, servername: 'npm.example' };
  let server: https.Server;
  let url = '';
  let requests: string[] = [];
  let answer: (res: ServerResponse) => void = () => {};

  beforeEach(async () => {
    requests = [];
    server = https.createServer({ cert: cert.pem, key: cert.key }, (req: IncomingMessage, res: ServerResponse) => {
      requests.push(`${req.method} ${req.url}`);
      answer(res);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = `https://127.0.0.1:${(server.address() as AddressInfo).port}/zetcert/latest`;
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  const answerWith = (status: number, body: string) => {
    answer = (res) => res.writeHead(status, { 'Content-Type': 'application/json' }).end(body);
  };
  const ask = (options: https.RequestOptions = trusted) => npmLatestVersion(new AbortController().signal, url, options);

  it('reads the version of the latest release', async () => {
    answerWith(200, JSON.stringify({ name: 'zetcert', version: '0.2.0', dist: { tarball: 'https://registry.npmjs.org/zetcert/-/zetcert-0.2.0.tgz' } }));
    expect(await ask()).toBe('0.2.0');
    expect(requests).toEqual(['GET /zetcert/latest']);
  });

  it.each([
    [404, '{"error": "not found"}'],
    [503, 'Service Unavailable'],
    [503, '{"version": "9.9.9"}'],
    [200, '<html>a login page</html>'],
    [200, 'null'],
    [200, '{"name": "zetcert"}'],
    [200, '{"version": 2}'],
  ])('rejects the answer %i %s', async (status, body) => {
    answerWith(status, body);
    await expect(ask()).rejects.toThrow();
  });

  it('rejects an answer that is too long', async () => {
    answerWith(200, JSON.stringify({ version: '0.2.0', readme: 'x'.repeat(100_000) }));
    await expect(ask()).rejects.toThrow('too long');
  });

  it("rejects a certificate it can't verify", async () => {
    answerWith(200, '{"version": "0.2.0"}');
    await expect(ask({ servername: 'npm.example' })).rejects.toThrow(/self.signed/);
    await expect(ask({ ca: cert.pem, servername: 'other.example' })).rejects.toThrow(/other\.example/);
    expect(requests).toEqual([]);
  });

  it('drops the connection when it is told to stop', async () => {
    answer = () => {};
    const closed = new Promise<void>((resolve) => server.once('secureConnection', (socket) => socket.once('close', () => resolve())));
    const stop = new AbortController();
    const pending = npmLatestVersion(stop.signal, url, trusted);
    await expect.poll(() => requests.length).toBe(1);
    stop.abort();
    await expect(pending).rejects.toThrow('aborted');
    await closed;
  });

  it('asks nothing when it was stopped before', async () => {
    const stop = new AbortController();
    stop.abort();
    await expect(npmLatestVersion(stop.signal, url, trusted)).rejects.toThrow('aborted');
    expect(requests).toEqual([]);
  });
});

describe('the lookup that can be stopped', () => {
  type Answer = { err: Error | null; address: string | LookupAddress[]; family?: number };

  /** Looks up through a resolver that knows these addresses; none is a failed query. IPv6 answers first. */
  function lookup(v4: string[], v6: string[], all: boolean): Promise<Answer> {
    const query = (addresses: string[], later: (fn: () => void) => void) => (_hostname: string, callback: (err: Error | null, addresses: string[]) => void) =>
      later(() => (addresses.length > 0 ? callback(null, addresses) : callback(new Error('queryA ENODATA'), [])));
    const resolver = { resolve4: query(v4, setImmediate), resolve6: query(v6, queueMicrotask) } as unknown as Resolver;
    return new Promise((resolve) => {
      stoppableLookup(resolver)('registry.npmjs.org', { all }, (err, address, family) => resolve({ err, address, family }));
    });
  }

  it('gives every address, IPv4 first', async () => {
    expect(await lookup(['203.0.113.7', '203.0.113.8'], ['2001:db8::7'], true)).toEqual({
      err: null,
      address: [
        { address: '203.0.113.7', family: 4 },
        { address: '203.0.113.8', family: 4 },
        { address: '2001:db8::7', family: 6 },
      ],
      family: undefined,
    });
  });

  it('gives the first address when one is asked for', async () => {
    expect(await lookup(['203.0.113.7', '203.0.113.8'], ['2001:db8::7'], false)).toEqual({ err: null, address: '203.0.113.7', family: 4 });
  });

  it('makes do with the family that answered', async () => {
    expect(await lookup([], ['2001:db8::7'], true)).toEqual({ err: null, address: [{ address: '2001:db8::7', family: 6 }], family: undefined });
    expect(await lookup([], ['2001:db8::7'], false)).toEqual({ err: null, address: '2001:db8::7', family: 6 });
    expect(await lookup(['203.0.113.7'], [], false)).toEqual({ err: null, address: '203.0.113.7', family: 4 });
  });

  it('fails when the name has no address', async () => {
    const r = await lookup([], [], true);
    expect(r.err?.message).toBe('no address for registry.npmjs.org');
    expect(r.address).toEqual([]);
  });
});
