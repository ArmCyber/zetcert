import { describe, expect, it } from 'vitest';
import type { CertbotCert, RenewalSettings } from '../../../src/certbot/reader';
import type { CertModel } from '../../../src/certs/model';
import { authHook, cleanupHook } from '../../../src/certbot/commands';
import { planCert, type PlanInput } from '../../../src/certs/planner';
import { snippetContent } from '../../../src/nginx/snippets';

function model(cert: string, names: string[], extra: Partial<CertModel> = {}): CertModel {
  return {
    cert,
    kind: 'regular',
    names: names.map((name) => ({ name, sources: [{ type: 'config' }] })),
    dropped: [],
    validation: names.some((n) => n.startsWith('*.')) ? 'dns' : 'http',
    challenge: 'auto',
    keyType: 'ecdsa',
    deploy: [],
    servers: [],
    skipped: [],
    included: true,
    newInclude: false,
    inConfig: false,
    snippetExists: true,
    unused: false,
    errors: [],
    warnings: [],
    ...extra,
  };
}

const webroot = (names: string[], extra: Partial<RenewalSettings> = {}): RenewalSettings => ({
  authenticator: 'webroot',
  webrootPath: ['/var/www/html'],
  webrootMap: Object.fromEntries(names.map((n) => [n, '/var/www/html'])),
  server: 'https://acme-v02.api.letsencrypt.org/directory',
  keyType: 'ecdsa',
  prefChalls: [],
  ...extra,
});

function actual(cert: string, names: string[], extra: Partial<CertbotCert> = {}, renewal?: Partial<RenewalSettings>): CertbotCert {
  return {
    name: cert,
    cert: {
      names,
      notBefore: new Date('2026-09-01'),
      notAfter: new Date('2026-11-30'),
      issuer: 'CN=E7',
      keyType: 'ecdsa',
      fingerprint: 'AA',
      serial: '01',
    },
    renewal: webroot(names, renewal),
    staging: false,
    ...extra,
  };
}

const plan = (input: Partial<PlanInput> & Pick<PlanInput, 'model'>) =>
  planCert({ webroot: '/var/www/html', certbotVersion: { major: 4, minor: 0, patch: 0, text: '4.0.0' }, ...input });

describe('planner', () => {
  const names = ['store.example', 'www.store.example'];
  const upToDate = {
    model: model('store', names),
    actual: actual('store', names),
    snippet: snippetContent('store', true),
    now: new Date('2026-09-20'),
  };

  it('leaves an up-to-date certificate alone', () => {
    expect(plan(upToDate)).toMatchObject({ action: 'none', add: [], remove: [], settings: [], snippet: 'ok' });
  });

  it('issues a new certificate', () => {
    expect(plan({ model: model('store', names) })).toMatchObject({
      action: 'issue',
      reason: 'new',
      add: names,
      forceRenewal: false,
      snippet: 'missing',
    });
  });

  it('adds and removes names without --force-renewal', () => {
    const p = plan({ ...upToDate, model: model('store', ['store.example', 'shop.store.example']) });
    expect(p).toMatchObject({
      action: 'issue',
      reason: 'names',
      add: ['shop.store.example'],
      remove: ['www.store.example'],
      forceRenewal: false,
    });
  });

  it('re-issues with --force-renewal for sync --force, staging and unreadable certificates', () => {
    expect(plan({ ...upToDate, force: true })).toMatchObject({ action: 'issue', reason: 'force', forceRenewal: true });
    expect(plan({ ...upToDate, actual: actual('store', names, { staging: true }) })).toMatchObject({
      action: 'issue',
      reason: 'staging',
      forceRenewal: true,
    });
    expect(plan({ ...upToDate, actual: actual('store', names, { cert: undefined }) })).toMatchObject({
      action: 'issue',
      reason: 'unreadable',
      forceRenewal: true,
    });
  });

  it('changes the key type with --force-renewal only on certbot < 2.0', () => {
    const rsa = { ...upToDate, model: model('store', names, { keyType: 'rsa' }) };
    expect(plan(rsa)).toMatchObject({ action: 'issue', reason: 'key-type', forceRenewal: false });
    expect(plan({ ...rsa, certbotVersion: { major: 1, minor: 21, patch: 0, text: '1.21.0' } })).toMatchObject({
      forceRenewal: true,
    });
  });

  it('fixes its own settings with reconfigure, or a new certificate before certbot 2.3', () => {
    const moved = { ...upToDate, webroot: '/srv/acme' };
    const p = plan(moved);
    expect(p.action).toBe('reconfigure');
    expect(p.settings).toEqual([
      { setting: 'webroot_path', saved: '/var/www/html', wanted: '/srv/acme', fix: 'reconfigure' },
      {
        setting: 'webroot_map',
        saved: 'store.example=/var/www/html,www.store.example=/var/www/html',
        wanted: 'every name=/srv/acme',
        fix: 'reconfigure',
      },
    ]);
    expect(plan({ ...moved, certbotVersion: { major: 2, minor: 2, patch: 0, text: '2.2.0' } })).toMatchObject({
      action: 'issue',
      reason: 'settings',
      forceRenewal: true,
    });
  });

  it('re-issues to remove hooks it does not know, an installer and DNS leftovers', () => {
    const p = plan({
      ...upToDate,
      actual: actual('store', names, {}, {
        authenticator: 'nginx',
        installer: 'nginx',
        deployHook: 'systemctl reload postfix',
        postHook: 'echo done',
        manualAuthHook: '/old/hook',
        prefChalls: ['dns-01'],
      }),
    });
    expect(p).toMatchObject({ action: 'issue', reason: 'settings', forceRenewal: true });
    expect(p.unknownHooks).toEqual([
      { kind: 'deploy', command: 'systemctl reload postfix' },
      { kind: 'post', command: 'echo done' },
    ]);
    expect(p.settings.map((s) => [s.setting, s.fix])).toEqual([
      ['deploy_hook', 'reissue'],
      ['post_hook', 'reissue'],
      ['installer', 'reissue'],
      ['authenticator', 'reconfigure'],
      ['manual_auth_hook', 'reissue'],
      ['pref_challs', 'reissue'],
    ]);
  });

  it('expects the manual hooks for DNS certificates', () => {
    const dns = model('wildcard.client.example', ['client.example', '*.client.example'], { kind: 'wildcard', validation: 'dns' });
    const saved = actual('wildcard.client.example', ['client.example', '*.client.example'], {}, {
      authenticator: 'manual',
      prefChalls: ['dns-01'],
      manualAuthHook: authHook('wildcard.client.example'),
      manualCleanupHook: cleanupHook('wildcard.client.example'),
      webrootPath: [],
      webrootMap: {},
    });
    expect(plan({ model: dns, actual: saved, snippet: snippetContent('wildcard.client.example', true) }).action).toBe('none');
    const fromHttp = actual('wildcard.client.example', ['client.example', '*.client.example']);
    const p = plan({ model: dns, actual: fromHttp, snippet: snippetContent('wildcard.client.example', true) });
    expect(p.action).toBe('reconfigure');
    expect(p.settings.map((s) => s.setting)).toEqual(['authenticator', 'pref_challs', 'manual_auth_hook', 'manual_cleanup_hook']);
    expect(authHook('x')).toBe('/usr/local/sbin/zetcert hook auth --cert x');
  });

  it('reports the snippet state', () => {
    expect(plan({ ...upToDate, snippet: snippetContent('store', false) }).snippet).toBe('placeholder');
    expect(plan({ ...upToDate, snippet: '# edited\n' }).snippet).toBe('outdated');
    expect(plan({ model: model('store', names), snippet: snippetContent('store', false) }).snippet).toBe('ok');
  });

  it('renews an expiring certificate, or one certbot failed to renew, without --force-renewal', () => {
    const failing = actual('store', names);
    failing.cert = { ...(failing.cert as NonNullable<CertbotCert['cert']>), notBefore: new Date('2026-09-01'), notAfter: new Date('2026-11-30') };
    const p = plan({ ...upToDate, actual: failing, now: new Date('2026-11-10') });
    expect(p).toMatchObject({ action: 'issue', reason: 'expiry', forceRenewal: false, expires: new Date('2026-11-30') });
    expect(plan({ ...upToDate, actual: failing, now: new Date('2026-09-20') }).action).toBe('none');
  });

  it('plans nothing for unused certificates', () => {
    const unused = model('wildcard.client.example', ['client.example', '*.client.example'], { unused: true, included: false });
    expect(plan({ model: unused, snippet: snippetContent('wildcard.client.example', false) })).toMatchObject({ action: 'none', snippet: 'ok' });
    expect(plan({ model: model('old', [], { unused: true, included: false }) }).blocked).toBeUndefined();
  });

  it('blocks certificates with errors or no names', () => {
    expect(plan({ model: model('empty', []) })).toMatchObject({ action: 'none', blocked: expect.stringMatching(/^no names/) });
    expect(plan({ model: model('bad', names, { errors: [{ message: 'too many' }] }) }).blocked).toBe('too many');
  });
});
