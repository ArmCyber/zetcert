// `zetcert status [cert]`.
import type { CertbotCert } from '../certbot/reader';
import {
  certHealth,
  checkExitCode,
  daysLeft,
  type Finding,
  isoDay,
  type Severity,
} from '../certs/health';
import type { CertModel, NameSource, WantedName } from '../certs/model';
import type { CertPlan } from '../certs/planner';
import { checkServed, type ServedResult, servedTargets } from '../nginx/served';
import { usesPlaceholder } from '../nginx/snippets';
import { supportFileChanges, TLS_CONF } from '../nginx/support';
import { UserError } from '../system/errors';
import { exists } from '../system/fs';
import { newerNpmCopy } from '../system/install';
import { formatLoc, type Loc } from '../system/loc';
import { type Loaded, loadAll, planAll, readSnippet } from './load';
import type { Output } from './output';
import type { Context } from './program';

export interface StatusOptions {
  check?: boolean;
}

function describeServed(served: ServedResult['served']): string {
  if (!served) return 'unknown';
  const names = served.names.length > 0 ? served.names.join(', ') : served.subject || 'no names';
  return `one for ${names}, expiring ${isoDay(served.notAfter)}`;
}

interface GlobalFinding {
  severity: Severity;
  message: string;
  loc?: Loc;
}

interface CertReport {
  model: CertModel;
  plan: CertPlan;
  actual?: CertbotCert;
  findings: Finding[];
}

function sourceText(source: NameSource, name: string): string {
  if (source.type === 'config') return 'config';
  if (source.type === 'wildcard') return 'certificate name';
  const at = formatLoc(source.loc);
  return source.raw.toLowerCase().replace(/\.$/, '') === name ? at : `${source.raw} at ${at}`;
}

function sourcesText(n: WantedName, verbose: boolean): string {
  const all = n.sources.map((s) => sourceText(s, n.name));
  const unique = [...new Set(all)];
  if (verbose || unique.length <= 3) return unique.join(', ');
  return `${unique.slice(0, 3).join(', ')} and ${unique.length - 3} more`;
}

function stateLabel(report: CertReport): { text: string; severity: Severity | 'ok' } {
  const { findings, plan } = report;
  const critical = findings.find((f) => f.severity === 'critical');
  if (critical) {
    const labels: Record<string, string> = {
      expiring: 'expiring',
      'renewal-failing': 'not renewing',
      placeholder: 'placeholder',
      served: 'wrong certificate served',
      'served-unchecked': "can't check what nginx serves",
    };
    return { text: labels[critical.code] ?? critical.code, severity: 'critical' };
  }
  if (plan.reason === 'new') return { text: 'new', severity: 'warning' };
  const warning = findings.find((f) => f.severity === 'warning');
  if (warning) {
    const labels: Record<string, string> = {
      pending: 'pending changes',
      blocked: 'blocked',
      skipped: 'skipped names',
      'too-many-names': 'many names',
    };
    return { text: labels[warning.code] ?? warning.code, severity: 'warning' };
  }
  if (findings.some((f) => f.code === 'unused')) return { text: 'unused', severity: 'info' };
  return { text: 'ok', severity: 'ok' };
}

function paint(out: Output, severity: Severity | 'ok', text: string): string {
  if (severity === 'critical') return out.red(text);
  if (severity === 'warning') return out.yellow(text);
  if (severity === 'ok') return out.green(text);
  return out.dim(text);
}

function expiryText(actual: CertbotCert | undefined, now: Date): string {
  if (!actual?.cert) return '—';
  const left = daysLeft(actual.cert.notAfter, now);
  return `${isoDay(actual.cert.notAfter)} (${left < 0 ? `${-left}d ago` : `${left}d`})`;
}

function printText(ctx: Context, reports: CertReport[], global: GlobalFinding[], single: boolean, now: Date) {
  const { out } = ctx;
  if (!single) {
    if (reports.length === 0) {
      out.info('No certificates: include /etc/nginx/zetcert/<cert>.conf in a server block, then run zetcert sync.');
    } else {
      const rows = reports.map((r) => {
        const state = stateLabel(r);
        return [
          r.model.cert,
          r.model.kind,
          r.model.validation,
          String(r.model.names.length),
          expiryText(r.actual, now),
          paint(out, state.severity, state.text),
        ];
      });
      for (const line of out.table(['CERTIFICATE', 'KIND', 'VALIDATION', 'NAMES', 'EXPIRES', 'STATE'], rows)) out.info(line);
    }
  }

  for (const r of reports) {
    const { model, actual } = r;
    out.info();
    const facts = [model.kind, model.validation === 'dns' ? `DNS${model.dnsAccount ? ` via ${model.dnsAccount}` : ''}` : 'HTTP', model.keyType];
    if (actual?.cert) facts.push(`expires ${isoDay(actual.cert.notAfter)}`);
    out.info(`${out.bold(model.cert)}  ${out.dim(facts.join(' · '))}`);
    const width = Math.max(0, ...model.names.map((n) => n.name.length));
    for (const n of model.names) {
      const inCert = actual?.cert?.names.includes(n.name) ?? false;
      const mark = actual?.cert && !inCert ? out.yellow(' (not in the certificate yet)') : '';
      out.info(`  ${n.name.padEnd(width)}  ${out.dim(sourcesText(n, out.verbose))}${mark}`);
    }
    if (model.names.length === 0) out.info(`  ${out.dim('(no names)')}`);
    for (const d of model.dropped) {
      out.info(`  ${out.dim(`not included: ${d.name} — ${d.reason} (${d.sources.map((s) => sourceText(s, d.name)).join(', ')})`)}`);
    }
    for (const f of r.findings) {
      if (f.code === 'unused' && !out.verbose && f.severity === 'info') {
        out.info(`  ${out.dim(f.message)}`);
        continue;
      }
      const label = f.code === 'pending' ? 'pending' : f.severity;
      const [first, ...rest] = f.message.split('\n');
      out.info(`  ${paint(out, f.severity, `${label}:`)} ${first}`);
      for (const line of rest) out.info(`  ${' '.repeat(label.length + 1)} ${line}`);
    }
    // The >25 names warning is already one of the findings.
    for (const w of model.warnings.filter((x) => x.code !== 'too-many-names')) {
      out.info(`  ${out.yellow('warning:')} ${w.loc ? `${formatLoc(w.loc)}: ` : ''}${w.message}`);
    }
    for (const s of model.skipped.filter((s) => s.warn)) {
      out.info(`  ${out.yellow('skipped:')} server_name ${JSON.stringify(s.raw)} at ${formatLoc(s)}: ${s.reason}`);
    }
    if (out.verbose) {
      for (const s of model.skipped.filter((s) => !s.warn)) {
        out.info(`  ${out.dim(`skipped: server_name ${JSON.stringify(s.raw)} at ${formatLoc(s)}: ${s.reason}`)}`);
      }
    }
  }
  if (global.length > 0) {
    out.info();
    for (const g of global) {
      const text = `${g.loc ? `${formatLoc(g.loc)}: ` : ''}${g.message}`;
      if (g.severity === 'info') out.info(out.dim(text));
      else out.warn(text);
    }
  }
}

function nameSourceJson(source: NameSource) {
  return source.type === 'nginx' ? { type: 'nginx', raw: source.raw, file: source.loc.file, line: source.loc.line } : source;
}

function toJson(reports: CertReport[], global: GlobalFinding[], ctx: Context, exitCode?: number) {
  return {
    initialized: ctx.initialized,
    certificates: reports.map(({ model, plan, actual, findings }) => ({
      name: model.cert,
      kind: model.kind,
      validation: model.validation,
      keyType: model.keyType,
      dnsAccount: model.dnsAccount ?? null,
      included: model.included,
      inConfig: model.inConfig,
      unused: model.unused,
      names: model.names.map((n) => ({ name: n.name, sources: n.sources.map(nameSourceJson) })),
      dropped: model.dropped.map((d) => ({ name: d.name, reason: d.reason, sources: d.sources.map(nameSourceJson) })),
      skippedServerNames: model.skipped.map((s) => ({ raw: s.raw, reason: s.reason, warning: s.warn, file: s.file, line: s.line })),
      certificate: actual?.cert
        ? {
            names: actual.cert.names,
            notBefore: actual.cert.notBefore.toISOString(),
            notAfter: actual.cert.notAfter.toISOString(),
            issuer: actual.cert.issuer,
            keyType: actual.cert.keyType,
            staging: actual.staging,
          }
        : null,
      pending: {
        action: plan.action,
        reason: plan.reason ?? null,
        add: plan.add,
        remove: plan.remove,
        settings: plan.settings,
        unknownHooks: plan.unknownHooks,
        snippet: plan.snippet,
        blocked: plan.blocked ?? null,
      },
      problems: [
        ...findings.map((f) => ({ severity: f.severity, code: f.code, message: f.message })),
        ...model.warnings.filter((w) => w.code !== 'too-many-names').map((w) => ({ severity: 'info', code: w.code ?? 'warning', message: w.message })),
      ],
    })),
    problems: global.map((g) => ({ severity: g.severity, message: g.message, file: g.loc?.file ?? null, line: g.loc?.line ?? null })),
    ...(exitCode === undefined ? {} : { check: exitCode }),
  };
}

export async function status(ctx: Context, certName: string | undefined, options: StatusOptions): Promise<number> {
  const { out } = ctx;
  if (!ctx.initialized) out.warn(`zetcert init hasn't run yet: using the default settings (${ctx.configPath} doesn't exist)`);
  const upgrade = newerNpmCopy();
  if (upgrade) {
    out.warn(`npm has zetcert ${upgrade.npm}, but the system copy is ${upgrade.system}: run sudo zetcert init to upgrade it`);
  }

  let loaded: Loaded;
  try {
    loaded = await loadAll(ctx.configPath);
  } catch (err) {
    // Whatever stops the check from running is critical for monitoring.
    out.error((err as Error).message);
    return options.check ? 2 : 1;
  }

  const now = new Date();
  const plans = planAll(loaded);
  let models = loaded.models;
  if (certName !== undefined) {
    models = models.filter((m) => m.cert === certName);
    if (models.length === 0) {
      throw new UserError(`no certificate named ${certName} (and no such command: zetcert --help lists them)`, options.check ? 2 : 1);
    }
  }

  const reports: CertReport[] = models.map((model) => {
    const plan = plans.get(model.cert) as CertPlan;
    const actual = loaded.certbot.get(model.cert);
    const findings = certHealth({
      model,
      plan,
      actual,
      placeholder: usesPlaceholder(readSnippet(model.cert)),
      skipped: loaded.state.certs[model.cert]?.skipped ?? [],
      now,
    });
    return { model, plan, actual, findings };
  });

  const global: GlobalFinding[] = [
    ...loaded.discovery.errors.map((e) => ({ severity: 'warning' as const, message: e.message, loc: e.loc })),
    ...loaded.discovery.warnings.map((w) => ({ severity: 'warning' as const, message: w.message, loc: w.loc })),
    ...loaded.discovery.missing.map((m) => ({
      severity: 'critical' as const,
      message: `the included file ${m.path} doesn't exist, so nginx -t fails`,
      loc: { file: m.file, line: m.line },
    })),
  ];

  if (ctx.initialized) {
    const support = supportFileChanges(loaded.config.config, loaded.discovery.supportIncludes);
    for (const change of support.changes) global.push({ severity: 'warning', message: `${change}: sudo zetcert sync does it` });
    if (support.tls.action === 'keep' && exists(TLS_CONF)) global.push({ severity: 'warning', message: support.tls.warning });
  }

  let exitCode: number | undefined;
  if (options.check) {
    const targets = servedTargets(loaded.discovery, readSnippet).filter((t) => certName === undefined || t.cert === certName);
    for (const result of await checkServed(targets)) {
      const report = reports.find((r) => r.model.cert === result.cert);
      if (!report || result.status === 'ok') continue;
      const where = `${result.name} on ${result.address} (${formatLoc(result.listen)})`;
      report.findings.push(
        result.status === 'mismatch'
          ? {
              severity: 'critical',
              code: 'served',
              message: `nginx serves a different certificate for ${where}: ${describeServed(result.served)}. Reload nginx, or check the include.`,
            }
          : {
              severity: 'critical',
              code: 'served-unchecked',
              message:
                result.status === 'no-file'
                  ? `can't check the certificate nginx serves for ${where}: the snippet or its certificate file is missing; run zetcert sync`
                  : `can't check the certificate nginx serves for ${where}: ${result.error}`,
            },
      );
    }
    exitCode = checkExitCode([...reports.flatMap((r) => r.findings), ...global.map((g) => ({ ...g, code: 'pending' as const }))]);
  }

  if (ctx.opts.json) out.print(JSON.stringify(toJson(reports, global, ctx, exitCode), null, 2));
  else printText(ctx, reports, global, certName !== undefined, now);

  if (exitCode !== undefined) return exitCode;
  return loaded.discovery.errors.length > 0 ? 1 : 0;
}
