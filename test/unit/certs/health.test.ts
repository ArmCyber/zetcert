import { describe, expect, it } from 'vitest';
import { planLines, renewalFailing, shellQuote } from '../../../src/certs/health';
import type { CertPlan } from '../../../src/certs/planner';

const plan = (extra: Partial<CertPlan>): CertPlan => ({
  cert: 'store',
  action: 'issue',
  add: [],
  remove: [],
  forceRenewal: false,
  settings: [],
  unknownHooks: [],
  snippet: 'ok',
  ...extra,
});

describe('planLines', () => {
  it('shows names, settings and the command that keeps an unknown hook', () => {
    expect(
      planLines(
        plan({
          reason: 'names',
          add: ['shop.store.example'],
          remove: ['old.store.example'],
          settings: [
            { setting: 'deploy_hook', saved: "echo 'hi'", wanted: '(removed)', fix: 'reissue' },
            { setting: 'installer', saved: 'nginx', wanted: '(removed)', fix: 'reissue' },
          ],
          unknownHooks: [{ kind: 'deploy', command: "echo 'hi'" }],
        }),
      ),
    ).toEqual([
      '+ shop.store.example  - old.store.example',
      'renewal settings: installer nginx → (removed)',
      `certbot deploy hook "echo 'hi'" will be removed; to keep it: zetcert update store --deploy 'echo '\\''hi'\\'''`,
    ]);
  });

  it("doesn't advise turning pre and post hooks into deploy commands", () => {
    const lines = planLines(plan({ reason: 'settings', unknownHooks: [{ kind: 'pre', command: 'systemctl stop nginx' }] }));
    expect(lines).toEqual([`certbot pre hook "systemctl stop nginx" will be removed: zetcert doesn't use pre or post hooks`]);
  });

  it('explains re-issues of unreadable and expiring certificates', () => {
    expect(planLines(plan({ reason: 'unreadable', add: ['a.example'] }))).toEqual(["re-issue: certbot's certificate file can't be read"]);
    expect(planLines(plan({ reason: 'expiry', expires: new Date('2026-10-01T00:00:00Z') }))).toEqual([
      "renew: it expires 2026-10-01 and certbot hasn't renewed it",
    ]);
  });

  it('says when an unknown hook is already in the deploy list', () => {
    const lines = planLines(plan({ reason: 'settings', unknownHooks: [{ kind: 'deploy', command: 'systemctl reload postfix' }] }), [
      'systemctl reload postfix',
    ]);
    expect(lines).toEqual([`certbot deploy hook "systemctl reload postfix" removed: it is in zetcert's deploy list`]);
  });

  it('quotes only when needed', () => {
    expect(shellQuote('systemctl')).toBe('systemctl');
    expect(shellQuote('systemctl reload postfix')).toBe("'systemctl reload postfix'");
  });
});

describe('renewalFailing', () => {
  it('is true with less than a quarter of the lifetime left', () => {
    const from = new Date('2026-01-01T00:00:00Z');
    const to = new Date('2026-04-01T00:00:00Z'); // 90 days
    expect(renewalFailing(from, to, new Date('2026-03-08T00:00:00Z'))).toBe(false); // 24 days left
    expect(renewalFailing(from, to, new Date('2026-03-10T00:00:00Z'))).toBe(true); // 22 days left
  });
});
