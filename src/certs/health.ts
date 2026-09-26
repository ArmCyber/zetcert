// Health of a certificate as `status` flags it, grouped the way `status --check` exits.
import type { CertbotCert } from '../certbot/reader';
import type { SkippedRecord } from '../system/state';
import type { CertModel } from './model';
import type { CertPlan } from './planner';

export type Severity = 'critical' | 'warning' | 'info';

export interface Finding {
  severity: Severity;
  code:
    | 'pending'
    | 'blocked'
    | 'skipped'
    | 'too-many-names'
    | 'renewal-failing'
    | 'expiring'
    | 'placeholder'
    | 'unused'
    | 'served'
    | 'served-unchecked';
  message: string;
}

const DAY = 86_400_000;
export const EXPIRING_DAYS = 7;

export function daysLeft(notAfter: Date, now: Date): number {
  return Math.floor((notAfter.getTime() - now.getTime()) / DAY);
}

/** Less than a quarter of the lifetime left: certbot should have renewed by now. */
export function renewalFailing(notBefore: Date, notAfter: Date, now: Date): boolean {
  const lifetime = notAfter.getTime() - notBefore.getTime();
  return notAfter.getTime() - now.getTime() < lifetime / 4;
}

export function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** Shell-quotes a command for a suggestion the user can paste. */
export function shellQuote(text: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(text) ? text : `'${text.replace(/'/g, `'\\''`)}'`;
}

/** The pending changes of a certificate, one line each. */
export function planLines(plan: CertPlan, deploy: string[] = []): string[] {
  if (plan.blocked) return [plan.blocked];
  const lines: string[] = [];
  if (plan.reason === 'new') lines.push(`new: ${plan.add.join(', ')}`);
  else if (plan.reason === 'unreadable') lines.push("re-issue: certbot's certificate file can't be read");
  else if (plan.add.length > 0 || plan.remove.length > 0) {
    lines.push([...plan.add.map((n) => `+ ${n}`), ...plan.remove.map((n) => `- ${n}`)].join('  '));
  } else if (plan.reason === 'force') lines.push('re-issue (--force)');
  else if (plan.reason === 'staging') lines.push('re-issue: the certificate is from the staging server');
  else if (plan.reason === 'key-type') lines.push('re-issue: new key type');
  else if (plan.reason === 'expiry') {
    lines.push(`renew: it expires ${plan.expires ? isoDay(plan.expires) : 'soon'} and certbot hasn't renewed it`);
  }
  const settings = plan.settings.filter((s) => !plan.unknownHooks.some((h) => s.setting === `${h.kind}_hook`));
  if (settings.length > 0) {
    const how = plan.action === 'reconfigure' ? ' (certbot reconfigure)' : plan.reason === 'settings' ? ' (new certificate)' : '';
    lines.push(`renewal settings${how}: ${settings.map((s) => `${s.setting} ${s.saved} → ${s.wanted}`).join(', ')}`);
  }
  for (const hook of plan.unknownHooks) {
    const text = `certbot ${hook.kind} hook ${JSON.stringify(hook.command)}`;
    if (hook.kind !== 'deploy') lines.push(`${text} will be removed: zetcert doesn't use pre or post hooks`);
    else if (deploy.includes(hook.command)) lines.push(`${text} removed: it is in zetcert's deploy list`);
    else lines.push(`${text} will be removed; to keep it: zetcert update ${plan.cert} --deploy ${shellQuote(hook.command)}`);
  }
  if (plan.snippet === 'missing') lines.push('snippet to create');
  else if (plan.snippet === 'placeholder') lines.push("snippet to point at certbot's certificate");
  else if (plan.snippet === 'outdated') lines.push('snippet to rewrite');
  return lines;
}

export function unusedMessage(cert: string): string {
  return `unused: no nginx include and not in the config. Include /etc/nginx/zetcert/${cert}.conf in its server blocks, or give it names in the config (zetcert update ${cert} --add <name>); zetcert delete ${cert} removes it`;
}

export function hasPendingChanges(plan: CertPlan): boolean {
  return plan.action !== 'none' || plan.snippet !== 'ok';
}

export interface HealthInput {
  model: CertModel;
  plan: CertPlan;
  actual?: CertbotCert;
  /** The snippet file points at the placeholder. */
  placeholder: boolean;
  skipped: SkippedRecord[];
  now: Date;
}

export function certHealth({ model, plan, actual, placeholder, skipped, now }: HealthInput): Finding[] {
  const findings: Finding[] = [];
  if (plan.blocked) findings.push({ severity: 'warning', code: 'blocked', message: plan.blocked });
  else if (hasPendingChanges(plan)) {
    findings.push({ severity: 'warning', code: 'pending', message: planLines(plan, model.deploy).join('\n') });
  }
  if (skipped.length > 0) {
    findings.push({
      severity: 'warning',
      code: 'skipped',
      message: `skipped by the last sync: ${skipped.map((s) => `${s.name} (${s.reason})`).join(', ')}`,
    });
  }
  const tooMany = model.warnings.find((w) => w.code === 'too-many-names');
  if (tooMany) findings.push({ severity: 'warning', code: 'too-many-names', message: tooMany.message });
  const cert = actual?.cert;
  if (cert) {
    const left = daysLeft(cert.notAfter, now);
    const when = `${isoDay(cert.notAfter)} (${left < 0 ? `${-left} days ago` : `in ${left} days`})`;
    if (left < EXPIRING_DAYS) {
      findings.push({ severity: 'critical', code: 'expiring', message: `${left < 0 ? 'expired' : 'expires'} ${when}` });
    } else if (renewalFailing(cert.notBefore, cert.notAfter, now)) {
      findings.push({
        severity: 'critical',
        code: 'renewal-failing',
        message: `not renewing: expires ${when}, and certbot should have renewed it with a quarter of its lifetime left`,
      });
    }
  }
  if (placeholder && model.included) {
    findings.push({
      severity: 'critical',
      code: 'placeholder',
      message: 'nginx uses the placeholder certificate: browsers show a warning for its names until it is issued',
    });
  }
  if (model.unused) {
    findings.push({ severity: 'info', code: 'unused', message: unusedMessage(model.cert) });
  }
  return findings;
}

/** `status --check`: 0 healthy, 1 warning, 2 critical. */
export function checkExitCode(findings: Finding[]): number {
  if (findings.some((f) => f.severity === 'critical')) return 2;
  if (findings.some((f) => f.severity === 'warning')) return 1;
  return 0;
}
