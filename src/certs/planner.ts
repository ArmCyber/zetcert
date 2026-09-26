// The planner compares what each certificate should be with what certbot has. It is a
// pure function: `status` shows its result, `sync` acts on it.
import { authHook, cleanupHook } from '../certbot/commands';
import type { CertbotCert, CertbotVersion } from '../certbot/reader';
import { versionAtLeast } from '../certbot/reader';
import { snippetContent, usesPlaceholder } from '../nginx/snippets';
import { daysLeft, EXPIRING_DAYS, renewalFailing } from './health';
import type { CertModel } from './model';

export type Action = 'issue' | 'reconfigure' | 'none';

export type IssueReason = 'new' | 'names' | 'force' | 'staging' | 'key-type' | 'expiry' | 'settings' | 'unreadable';

export interface SettingFix {
  /** The renewal setting, as certbot names it. */
  setting: string;
  saved: string;
  wanted: string;
  /** zetcert's own values are fixed with `certbot reconfigure`; values that must go need a new certificate. */
  fix: 'reconfigure' | 'reissue';
}

export interface UnknownHook {
  kind: 'deploy' | 'pre' | 'post';
  command: string;
}

export type SnippetState =
  | 'ok'
  /** No snippet file yet. */
  | 'missing'
  /** Points at the placeholder, but certbot has the certificate. */
  | 'placeholder'
  /** Differs from what zetcert writes, e.g. edited by hand. */
  | 'outdated';

export interface CertPlan {
  cert: string;
  action: Action;
  reason?: IssueReason;
  /** Names to add to and remove from the certificate certbot has. */
  add: string[];
  remove: string[];
  /** certbot needs --force-renewal: the names are unchanged but a new certificate is needed. */
  forceRenewal: boolean;
  settings: SettingFix[];
  unknownHooks: UnknownHook[];
  snippet: SnippetState;
  /** Why nothing can be done for the certificate, e.g. it has no names or its config is wrong. */
  blocked?: string;
  /** For reason `expiry`: when the certificate expires. */
  expires?: Date;
}

export interface PlanInput {
  model: CertModel;
  /** What certbot has for this certificate name. */
  actual?: CertbotCert;
  /** The snippet file's current content. */
  snippet?: string;
  webroot: string;
  /** Undefined when unknown: then the newest behaviour is assumed. */
  certbotVersion?: CertbotVersion;
  force?: boolean;
  now?: Date;
}

const show = (value: string | string[] | undefined) =>
  value === undefined || (Array.isArray(value) && value.length === 0) ? '(none)' : Array.isArray(value) ? value.join(',') : value;

function compareSettings(input: PlanInput, actual: CertbotCert): { fixes: SettingFix[]; hooks: UnknownHook[] } {
  const { model, webroot } = input;
  const saved = actual.renewal;
  const fixes: SettingFix[] = [];
  const hooks: UnknownHook[] = [];
  const own = (setting: string, have: string | string[] | undefined, want: string) => {
    fixes.push({ setting, saved: show(have), wanted: want, fix: 'reconfigure' });
  };
  const mustGo = (setting: string, have: string | string[]) => {
    fixes.push({ setting, saved: show(have), wanted: '(removed)', fix: 'reissue' });
  };

  if (saved.deployHook) hooks.push({ kind: 'deploy', command: saved.deployHook });
  if (saved.preHook) hooks.push({ kind: 'pre', command: saved.preHook });
  if (saved.postHook) hooks.push({ kind: 'post', command: saved.postHook });
  for (const hook of hooks) mustGo(`${hook.kind}_hook`, hook.command);
  if (saved.installer) mustGo('installer', saved.installer);

  if (model.validation === 'http') {
    if (saved.authenticator !== 'webroot') own('authenticator', saved.authenticator, 'webroot');
    if (saved.webrootPath.length !== 1 || saved.webrootPath[0] !== webroot) own('webroot_path', saved.webrootPath, webroot);
    const mapped = Object.entries(saved.webrootMap).filter(([, path]) => path !== webroot);
    if (mapped.length > 0) own('webroot_map', mapped.map(([name, path]) => `${name}=${path}`), `every name=${webroot}`);
    // Leftovers of DNS validation: `reconfigure` would keep them, so they need a new certificate.
    if (saved.manualAuthHook) mustGo('manual_auth_hook', saved.manualAuthHook);
    if (saved.manualCleanupHook) mustGo('manual_cleanup_hook', saved.manualCleanupHook);
    if (saved.prefChalls.some((c) => c !== 'http-01')) mustGo('pref_challs', saved.prefChalls);
  } else {
    if (saved.authenticator !== 'manual') own('authenticator', saved.authenticator, 'manual');
    if (saved.prefChalls.length !== 1 || saved.prefChalls[0] !== 'dns-01') own('pref_challs', saved.prefChalls, 'dns-01');
    if (saved.manualAuthHook !== authHook(model.cert)) own('manual_auth_hook', saved.manualAuthHook, authHook(model.cert));
    if (saved.manualCleanupHook !== cleanupHook(model.cert)) {
      own('manual_cleanup_hook', saved.manualCleanupHook, cleanupHook(model.cert));
    }
  }
  return { fixes, hooks };
}

function dueForRenewal(cert: { notBefore: Date; notAfter: Date }, now: Date): boolean {
  return daysLeft(cert.notAfter, now) < EXPIRING_DAYS || renewalFailing(cert.notBefore, cert.notAfter, now);
}

function snippetState(cert: string, current: string | undefined, certbotHasIt: boolean): SnippetState {
  if (current === undefined) return 'missing';
  if (current === snippetContent(cert, certbotHasIt)) return 'ok';
  return certbotHasIt && usesPlaceholder(current) ? 'placeholder' : 'outdated';
}

export function planCert(input: PlanInput): CertPlan {
  const { model, actual } = input;
  const plan: CertPlan = {
    cert: model.cert,
    action: 'none',
    add: [],
    remove: [],
    forceRenewal: false,
    settings: [],
    unknownHooks: [],
    // A certificate only in the config, with no include and no snippet (e.g. for postfix), needs none.
    snippet: !model.included && input.snippet === undefined ? 'ok' : snippetState(model.cert, input.snippet, actual !== undefined),
  };
  const issue = (reason: IssueReason, forceRenewal: boolean) => {
    plan.action = 'issue';
    plan.reason = reason;
    plan.forceRenewal = forceRenewal;
  };

  // No include left and not in the config: nothing to plan until it is used again or deleted.
  if (model.unused) return { ...plan, snippet: 'ok' };
  if (model.errors.length > 0) {
    plan.blocked = model.errors.map((e) => e.message).join('; ');
    return plan;
  }
  const wanted = model.names.map((n) => n.name);
  if (wanted.length === 0) {
    plan.blocked = 'no names: no server block with a usable server_name includes it, and the config adds none';
    return plan;
  }
  if (!actual) {
    plan.add = wanted;
    issue('new', false);
    return plan;
  }

  const { fixes, hooks } = compareSettings(input, actual);
  plan.settings = fixes;
  plan.unknownHooks = hooks;
  if (!actual.cert) {
    plan.add = wanted;
    issue('unreadable', true);
    return plan;
  }
  const have = new Set(actual.cert.names);
  const want = new Set(wanted);
  plan.add = wanted.filter((n) => !have.has(n));
  plan.remove = actual.cert.names.filter((n) => !want.has(n));

  const version = input.certbotVersion;
  const keyTypeChange =
    actual.cert.keyType !== model.keyType || (actual.renewal.keyType !== undefined && actual.renewal.keyType !== model.keyType);
  if (plan.add.length > 0 || plan.remove.length > 0) issue('names', false);
  else if (input.force) issue('force', true);
  else if (actual.staging) issue('staging', true);
  else if (keyTypeChange) issue('key-type', version === undefined ? false : !versionAtLeast(version, 2, 0));
  else if (dueForRenewal(actual.cert, input.now ?? new Date())) {
    // Expired, or certbot hasn't renewed it in time: certbot renews it, since it is due.
    issue('expiry', false);
    plan.expires = actual.cert.notAfter;
  } else if (fixes.some((f) => f.fix === 'reissue')) issue('settings', true);
  else if (fixes.length > 0) {
    if (version === undefined || versionAtLeast(version, 2, 3)) plan.action = 'reconfigure';
    else issue('settings', true);
  }
  return plan;
}
