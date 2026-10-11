// The update check: once a day, asks npm for the latest zetcert and keeps the answer in
// /var/lib/zetcert/update.json. It only ever leads to a note, so nothing here may fail a command or
// hold it up: npm gets a short time to answer, and whatever goes wrong is ignored until the next run.
import { type LookupAddress, Resolver } from 'node:dns';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import { readText, writeFileAtomic } from './fs';
import { compareVersions } from './install';
import { UPDATE_FILE } from './paths';

const LATEST_URL = 'https://registry.npmjs.org/zetcert/latest';
const DAY_MS = 86_400_000;
/** How long npm gets to answer, from the start of the command. */
const TIMEOUT_MS = 2000;
/** A DNS server that doesn't answer gets twice this long (c-ares), then the next one is asked. */
const DNS_TIMEOUT_MS = 500;
/** npm's answer is about 2 kB. */
const MAX_ANSWER = 64 * 1024;
/** A version is saved and printed, so nothing else gets through. */
const VERSION_FORMAT = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

/** Asks for the latest version. Rejects when there is no answer. */
export type LatestVersion = (signal: AbortSignal) => Promise<string>;

/**
 * A lookup that can be stopped. The system's (getaddrinfo) can't: while a DNS server doesn't
 * answer, it keeps the process alive long after the request was given up.
 */
export function stoppableLookup(resolver: Pick<Resolver, 'resolve4' | 'resolve6'>): LookupFunction {
  return (hostname, options, callback) => {
    const found: LookupAddress[] = [];
    let pending = 2;
    const collect = (family: 4 | 6) => (err: Error | null, addresses: string[]) => {
      if (!err) found.push(...addresses.map((address) => ({ address, family })));
      if (--pending > 0) return;
      // IPv4 first: on a server without it, those addresses fail at once and IPv6 is next.
      found.sort((a, b) => a.family - b.family);
      const [first] = found;
      if (!first) callback(new Error(`no address for ${hostname}`), []);
      else if (options.all) callback(null, found);
      else callback(null, first.address, first.family);
    };
    resolver.resolve4(hostname, collect(4));
    resolver.resolve6(hostname, collect(6));
  };
}

/**
 * GETs a small JSON document. When the signal fires, the lookup and the connection are dropped at
 * once. Node's fetch isn't used: after an aborted request it keeps the process alive until its own
 * 10-second connect timeout.
 */
function getJson(url: string, signal: AbortSignal, options: https.RequestOptions): Promise<unknown> {
  const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  const stopLookup = () => resolver.cancel();
  signal.addEventListener('abort', stopLookup, { once: true });
  return new Promise<unknown>((resolve, reject) => {
    const request = https.get(url, { agent: false, lookup: stoppableLookup(resolver), signal, ...options }, (response) => {
      if (response.statusCode !== 200) {
        request.destroy();
        reject(new Error(`HTTP ${response.statusCode}`));
        return;
      }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk: string) => {
        body += chunk;
        if (body.length > MAX_ANSWER) {
          request.destroy();
          reject(new Error('the answer is too long'));
        }
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err as Error);
        }
      });
    });
    request.on('error', reject);
  }).finally(() => {
    signal.removeEventListener('abort', stopLookup);
    // Also after an answer: on Node 20, a resolver whose server didn't answer lingers for a while.
    resolver.cancel();
  });
}

/** The latest zetcert on npm. The url and the options are for tests: a local server and its certificate. */
export async function npmLatestVersion(signal: AbortSignal, url = LATEST_URL, options: https.RequestOptions = {}): Promise<string> {
  const answer = (await getJson(url, signal, options)) as { version?: unknown } | null;
  if (typeof answer?.version !== 'string') throw new Error('no version in the answer');
  return answer.version;
}

interface Saved {
  /** ISO time of npm's last answer. */
  checked: string;
  latest: string;
}

/** A missing or broken file counts as never asked. */
function readSaved(): Saved | undefined {
  try {
    const raw = JSON.parse(readText(UPDATE_FILE) ?? '') as Partial<Saved> | null;
    return typeof raw?.checked === 'string' && typeof raw.latest === 'string' && VERSION_FORMAT.test(raw.latest)
      ? { checked: raw.checked, latest: raw.latest }
      : undefined;
  } catch {
    return undefined;
  }
}

export interface UpdateCheck {
  /** The latest version when it is newer than the running one. Never rejects. */
  readonly newer: Promise<string | undefined>;
  /** Stops waiting for npm. */
  cancel(): void;
}

/**
 * Looks for a version newer than `running`: in the saved answer when npm answered less than a day
 * ago, else by asking npm, which runs in the background until `newer` is awaited.
 */
export function startUpdateCheck(running: string, latestVersion: LatestVersion = npmLatestVersion, now = new Date()): UpdateCheck {
  const saved = readSaved();
  const age = saved ? now.getTime() - Date.parse(saved.checked) : NaN;
  const stop = new AbortController();

  const ask = async (): Promise<string | undefined> => {
    const timer = setTimeout(() => stop.abort(), TIMEOUT_MS);
    let latest: string;
    try {
      latest = await Promise.race([
        latestVersion(stop.signal),
        // Whatever the request does, the wait ends with the signal.
        new Promise<never>((_, reject) => stop.signal.addEventListener('abort', () => reject(new Error('stopped')), { once: true })),
      ]);
    } catch {
      // No answer: the last one still counts, and the next run asks again.
      return saved?.latest;
    } finally {
      clearTimeout(timer);
    }
    if (!VERSION_FORMAT.test(latest)) return saved?.latest;
    try {
      writeFileAtomic(UPDATE_FILE, `${JSON.stringify({ checked: now.toISOString(), latest } satisfies Saved, null, 2)}\n`, 0o644);
    } catch {
      // Not saved: the next run asks again.
    }
    return latest;
  };

  // A time in the future means the clock was wrong when it was saved: ask again.
  const latest = saved && age >= 0 && age < DAY_MS ? Promise.resolve<string | undefined>(saved.latest) : ask();
  return {
    newer: latest.then((version) => (version !== undefined && compareVersions(version, running) > 0 ? version : undefined)),
    cancel: () => stop.abort(),
  };
}
