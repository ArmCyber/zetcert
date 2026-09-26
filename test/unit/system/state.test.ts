import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { emptyState, issuedWithin, loadState, recordIssued, saveState } from '../../../src/system/state';
import { tempRoot } from '../helpers';

describe('state', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it('is empty when the file is missing or broken', () => {
    expect(loadState()).toEqual(emptyState());
    root.write('/var/lib/zetcert/state.json', '{ not json');
    expect(loadState()).toEqual(emptyState());
    root.write('/var/lib/zetcert/state.json', '[1, 2]');
    expect(loadState()).toEqual(emptyState());
    root.write('/var/lib/zetcert/state.json', '{"certs": {"a": {"skipped": [1, {"name": "x.a.example", "reason": "r", "at": "t"}], "issued": "no"}}, "zones": 5}');
    expect(loadState()).toEqual({
      certs: { a: { skipped: [{ name: 'x.a.example', reason: 'r', at: 't' }], issued: [] } },
      zones: {},
      alerts: {},
    });
  });

  it('saves and loads', () => {
    const state = emptyState();
    state.certs.store = { skipped: [{ name: 'old.store.example', reason: 'no A/AAAA record', at: '2026-09-26T00:00:00.000Z' }], issued: [] };
    state.zones['cf-main'] = { zones: [{ id: 'z1', name: 'client.example' }], at: '2026-09-26T00:00:00.000Z' };
    state.alerts.store = { expiring: '2026-09-26' };
    saveState(state);
    expect(loadState()).toEqual(state);
  });

  it('counts issuances in the last days', () => {
    const state = emptyState();
    const now = new Date('2026-09-26T12:00:00Z');
    for (const day of ['2026-09-10', '2026-09-20', '2026-09-24', '2026-09-26']) {
      recordIssued(state, 'a', new Date(`${day}T10:00:00Z`));
    }
    expect(issuedWithin(state, 'a', 7, now)).toBe(3);
    expect(issuedWithin(state, 'b', 7, now)).toBe(0);
    recordIssued(state, 'a', new Date('2026-11-01T00:00:00Z'));
    expect(state.certs.a?.issued).toEqual(['2026-11-01T00:00:00.000Z']);
  });
});
