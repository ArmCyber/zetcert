// /var/lib/zetcert/state.json: a cache of skipped names, issuance history, DNS zones and the last
// alerts. A missing or broken file counts as empty.
import { readText, writeFileAtomic } from './fs';
import { STATE_FILE } from './paths';

export interface SkippedRecord {
  name: string;
  reason: string;
  /** ISO time of the sync that skipped it. */
  at: string;
}

export interface CertState {
  /** Names the last sync left out, with the reason. */
  skipped: SkippedRecord[];
  /** ISO times of issuances, newest last. */
  issued: string[];
}

export interface CachedZone {
  id: string;
  name: string;
}

export interface State {
  certs: Record<string, CertState>;
  /** DNS zones per account. */
  zones: Record<string, { zones: CachedZone[]; at: string }>;
  /** The day (YYYY-MM-DD) each alert was last sent, per certificate and event. */
  alerts: Record<string, Record<string, string>>;
}

export function emptyState(): State {
  return { certs: {}, zones: {}, alerts: {} };
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function loadState(): State {
  let raw: unknown;
  try {
    raw = JSON.parse(readText(STATE_FILE) ?? '{}');
  } catch {
    return emptyState();
  }
  if (!isObject(raw)) return emptyState();
  const state = emptyState();
  if (isObject(raw.certs)) {
    for (const [cert, value] of Object.entries(raw.certs)) {
      if (!isObject(value)) continue;
      state.certs[cert] = {
        skipped: Array.isArray(value.skipped)
          ? value.skipped.filter(
              (s): s is SkippedRecord => isObject(s) && typeof s.name === 'string' && typeof s.reason === 'string',
            )
          : [],
        issued: Array.isArray(value.issued) ? value.issued.filter((t): t is string => typeof t === 'string') : [],
      };
    }
  }
  if (isObject(raw.zones)) {
    for (const [account, value] of Object.entries(raw.zones)) {
      if (isObject(value) && Array.isArray(value.zones) && typeof value.at === 'string') {
        state.zones[account] = {
          zones: value.zones.filter((z): z is CachedZone => isObject(z) && typeof z.id === 'string' && typeof z.name === 'string'),
          at: value.at,
        };
      }
    }
  }
  if (isObject(raw.alerts)) {
    for (const [cert, value] of Object.entries(raw.alerts)) {
      if (!isObject(value)) continue;
      state.alerts[cert] = Object.fromEntries(Object.entries(value).filter(([, day]) => typeof day === 'string')) as Record<
        string,
        string
      >;
    }
  }
  return state;
}

export function saveState(state: State): void {
  writeFileAtomic(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`, 0o644);
}

export function certState(state: State, cert: string): CertState {
  state.certs[cert] ??= { skipped: [], issued: [] };
  return state.certs[cert];
}

/** How many times the certificate was issued in the last `days` days. */
export function issuedWithin(state: State, cert: string, days: number, now: Date): number {
  const since = now.getTime() - days * 86_400_000;
  return (state.certs[cert]?.issued ?? []).filter((t) => Date.parse(t) >= since).length;
}

export function recordIssued(state: State, cert: string, now: Date): void {
  const s = certState(state, cert);
  // Keep a few weeks: enough for the rate-limit warning.
  const since = now.getTime() - 30 * 86_400_000;
  s.issued = [...s.issued.filter((t) => Date.parse(t) >= since), now.toISOString()];
}
