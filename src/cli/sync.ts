// `zetcert sync [cert…]`: the main command, in numbered steps.
import { certonlyArgs, type IssueSettings, reconfigureArgs } from '../certbot/commands';
import { failureSummary } from '../certbot/errors';
import { certbotVersion, readAccounts, readCertbotCerts, readCertFile } from '../certbot/reader';
import { runCertbot } from '../certbot/runner';
import { planLines, unusedMessage } from '../certs/health';
import { buildModel, type CertModel } from '../certs/model';
import { type CertPlan, planCert } from '../certs/planner';
import { type Config, loadConfig } from '../config/config';
import { type Discovery, discover } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { ParseError } from '../nginx/parser';
import { existingSnippets, PLACEHOLDER_CERT, snippetPath, writeSnippet } from '../nginx/snippets';
import { ACME_CONF, acmeConfContent, supportFileChanges, TLS_CONF, tlsFilePlan } from '../nginx/support';
import { loadDnsAccountsSafe } from '../config/dns-accounts';
import { driverFor } from '../dns/index';
import { describeFailures, ZoneFinder } from '../dns/zones';
import { precheckNames, type PrecheckContext } from '../precheck/index';
import { localPublicIps } from '../precheck/ips';
import { systemLookup } from '../precheck/lookup';
import { UserError } from '../system/errors';
import { FileBatch } from '../system/files';
import { readText } from '../system/fs';
import { acquireLock } from '../system/lock';
import { formatLoc } from '../system/loc';
import { certState, issuedWithin, loadState, recordIssued, saveState, type SkippedRecord } from '../system/state';
import { readSnippet } from './load';
import { nginxReload, nginxTest, runDeploy } from './nginx';
import type { Context } from './program';

export interface SyncOptions {
  dryRun?: boolean;
  force?: boolean;
  strict?: boolean;
  /** false with --no-reload. */
  reload?: boolean;
  /** false with --no-precheck. */
  precheck?: boolean;
}

interface Entry {
  model: CertModel;
  plan: CertPlan;
  skipped: SkippedRecord[];
  warnings: string[];
  /** DNS validation: the accounts that manage the names' zones. */
  dnsAccounts?: string[];
  failed?: string;
  /** certbot didn't do what the plan expected, e.g. "not yet due". */
  incomplete?: boolean;
  issued?: boolean;
  reconfigured?: boolean;
}

/** Step 2: the nginx config must parse; the only missing files allowed are new snippets. */
function readNginx(config: Config): Discovery {
  let discovery: Discovery;
  try {
    discovery = discover(loadNginxConfig(config.nginx.config));
  } catch (err) {
    if (err instanceof ParseError) throw new UserError(`the nginx config has an error, so nothing was done:\n${err.message}`);
    throw err;
  }
  const problems = [
    ...discovery.errors.map((e) => `${formatLoc(e.loc)}: ${e.message}`),
    // zetcert's own _acme.conf and _tls.conf are written in step 3 when they are missing.
    ...discovery.missing
      .filter((m) => m.path !== ACME_CONF && !(m.path === TLS_CONF && config.tls !== 'off'))
      .map((m) => `${formatLoc(m)}: the included file ${m.path} doesn't exist`),
  ];
  if (problems.length > 0) throw new UserError(`the nginx config has errors, so nothing was done:\n${problems.join('\n')}`);
  return discovery;
}

function issueSettings(model: CertModel, config: Config): IssueSettings {
  return {
    cert: model.cert,
    names: model.names.map((n) => n.name),
    keyType: model.keyType,
    validation: model.validation,
    webroot: config.webroot,
    email: config.email,
  };
}

function withoutNames(model: CertModel, names: Set<string>): CertModel {
  return { ...model, names: model.names.filter((n) => !names.has(n.name)) };
}

/** D and *.D of a wildcard.D certificate, which it always contains. */
function coreNames(model: CertModel): Set<string> {
  return model.domain ? new Set([model.domain, `*.${model.domain}`]) : new Set();
}

/** The certificate's names an ACME identifier stands for: `x` is the identifier of both x and *.x. */
function namesOfIdentifier(model: CertModel, identifier: string): string[] {
  return model.names.map((n) => n.name).filter((n) => n === identifier || n === `*.${identifier}`);
}

const NO_NAMES_LEFT = 'no names left: every name was skipped (see below)';

export async function sync(ctx: Context, only: string[], options: SyncOptions): Promise<number> {
  const lock = acquireLock();
  try {
    return await run(ctx, only, options);
  } finally {
    lock.release();
  }
}

async function run(ctx: Context, only: string[], options: SyncOptions): Promise<number> {
  const { out } = ctx;
  const dryRun = options.dryRun === true;
  const now = new Date();

  // 1. The config (the lock is taken).
  const config = loadConfig(ctx.configPath).config;
  if (!readCertFile(PLACEHOLDER_CERT)) throw new UserError('the placeholder certificate is missing: run zetcert init');

  // 2. The nginx config.
  let discovery = readNginx(config);
  let certbot = new Map(readCertbotCerts().map((c) => [c.name, c]));

  // 3. Snippets for new certificates (also with --dry-run: nginx -t needs them), and zetcert's
  // support files if nginx includes one that is missing.
  const created = new FileBatch();
  const newCerts = [...new Set(discovery.snippetIncludes.filter((s) => !s.exists).map((s) => s.cert))];
  for (const cert of newCerts) {
    const include = discovery.snippetIncludes.find((s) => s.cert === cert) as { file: string; line: number };
    if (!(await ctx.prompt.confirm(`New certificate ${cert}, included at ${formatLoc(include)}: create its snippet?`))) {
      throw new UserError(`nginx -t fails without the snippet of ${cert}, so nothing was done`);
    }
    writeSnippet(created, cert, certbot.has(cert));
    out.info(`Created ${snippetPath(cert)} (${certbot.has(cert) ? "certbot's certificate" : 'placeholder until it is issued'}).`);
  }
  for (const missing of discovery.missing) {
    if (missing.path === ACME_CONF) created.write(ACME_CONF, acmeConfContent(config.webroot), 0o644);
    if (missing.path === TLS_CONF && config.tls !== 'off') {
      const plan = tlsFilePlan(config.tls, discovery.supportIncludes);
      if (plan.action === 'write') created.write(TLS_CONF, plan.content, 0o644);
    }
  }
  if (created.changed.length > 0) discovery = readNginx(config);

  // 4. nginx -t, before anything is issued.
  const test = await nginxTest(config);
  if (!test.ok) throw new UserError(`nginx -t failed, so nothing was issued:\n${test.output}`);

  // 5. The wanted names of every certificate.
  let models = buildModel({ config, discovery, snippets: existingSnippets() });
  const unknown = only.filter((c) => !models.some((m) => m.cert === c));
  if (unknown.length > 0) throw new UserError(`no certificate named ${unknown.join(', ')}`);
  if (only.length > 0) models = models.filter((m) => only.includes(m.cert));

  const version = await certbotVersion();
  if (!version) throw new UserError('certbot is not installed');
  const planFor = (model: CertModel) =>
    planCert({
      model,
      actual: certbot.get(model.cert),
      snippet: readSnippet(model.cert),
      webroot: config.webroot,
      certbotVersion: version,
      force: options.force,
    });
  const entries: Entry[] = models.map((model) => ({ model, plan: planFor(model), skipped: [], warnings: [] }));

  // The pre-checks and Let's Encrypt validate against the nginx that is running. When step 3
  // created files, or _acme.conf is outdated (a new webroot), write _acme.conf and reload first.
  const acmeNow = readText(ACME_CONF);
  const acmeOutdated = acmeNow !== undefined && acmeNow !== acmeConfContent(config.webroot);
  const certbotWork = entries.some((e) => !e.model.unused && !e.plan.blocked && e.plan.action !== 'none');
  if (!dryRun && options.reload !== false && certbotWork && (created.changed.length > 0 || acmeOutdated)) {
    const early = new FileBatch();
    if (acmeOutdated) {
      early.write(ACME_CONF, acmeConfContent(config.webroot), 0o644);
      const retest = await nginxTest(config);
      if (!retest.ok) {
        early.restore();
        throw new UserError(`nginx -t failed with the new ${ACME_CONF}, so the previous one is back and nothing was issued:\n${retest.output}`);
      }
    }
    const reload = await nginxReload(config);
    if (!reload.ok) throw new UserError(`reloading nginx failed, so nothing was issued: ${reload.output}`);
    out.info('Reloaded nginx, so validation sees the new files.');
  }

  // 6. Pre-checks on every name that would be issued. DNS validation first needs an account that
  // manages each name's zone; without one the certificate fails and the others go on.
  if (options.precheck !== false && entries.some((e) => e.model.validation === 'dns' && e.plan.action !== 'none')) {
    const { accounts, problems } = loadDnsAccountsSafe();
    for (const problem of problems) out.warn(problem);
    const zoneState = loadState();
    const finder = new ZoneFinder(accounts, zoneState, driverFor);
    for (const entry of entries.filter((e) => e.model.validation === 'dns' && e.plan.action !== 'none' && !e.plan.blocked && !e.model.unused)) {
      const pinned = entry.model.dnsAccount;
      if (pinned && !accounts.some((a) => a.name === pinned)) {
        entry.failed = `the DNS account ${pinned} (dns: in the config) doesn't exist: run zetcert dns add ${pinned} …`;
        continue;
      }
      const used = new Set<string>();
      const missing: string[] = [];
      for (const n of entry.model.names) {
        let match;
        try {
          match = await finder.find(n.name, pinned);
        } catch (err) {
          entry.failed = `the zones of the DNS accounts can't be listed: ${(err as Error).message}`;
          break;
        }
        if (match) used.add(match.account.name);
        else missing.push(n.name.replace(/^\*\./, ''));
      }
      if (entry.failed) continue;
      if (missing.length > 0) {
        const names = [...new Set(missing)].join(', ');
        const failures = describeFailures(finder);
        entry.failed = pinned
          ? `the DNS account ${pinned} has no zone for ${names}`
          : `no DNS account manages ${names}: run zetcert dns add …`;
        if (failures.length > 0) entry.failed += ` (${failures.join('; ')})`;
      }
      entry.dnsAccounts = [...used];
    }
    for (const failure of describeFailures(finder)) out.warn(failure);
    if (!dryRun) saveState(zoneState);
  }
  if (options.precheck !== false) {
    const accounts = readAccounts();
    const precheck: PrecheckContext = {
      webroot: config.webroot,
      httpAddress: config.precheck.http_address,
      publicIps: [...new Set([...config.public_ips, ...localPublicIps()])],
      accountUris: [...accounts.values()],
      lookup: systemLookup(),
    };
    for (const entry of entries.filter((e) => e.plan.action === 'issue' && !e.failed && !e.model.unused)) {
      const saved = certbot.get(entry.model.cert)?.renewal.account;
      const accountUris = saved && accounts.has(saved) ? [accounts.get(saved) as string] : precheck.accountUris;
      const names = entry.model.names.map((n) => n.name);
      const results = await precheckNames(names, entry.model.validation, { ...precheck, accountUris });
      for (const r of results) entry.warnings.push(...r.warnings);
      const bad = results.filter((r) => !r.ok);
      if (bad.length === 0) continue;
      if (options.strict) {
        entry.failed = `pre-check failed (--strict): ${bad.map((b) => `${b.name}: ${b.reason}`).join('; ')}`;
        continue;
      }
      const core = bad.filter((b) => coreNames(entry.model).has(b.name));
      if (core.length > 0) {
        entry.failed = `${entry.model.cert} always contains ${entry.model.domain} and *.${entry.model.domain}: ${core.map((b) => `${b.name}: ${b.reason}`).join('; ')}`;
        continue;
      }
      entry.skipped.push(...bad.map((b) => ({ name: b.name, reason: b.reason ?? 'pre-check failed', at: now.toISOString() })));
      entry.model = withoutNames(entry.model, new Set(bad.map((b) => b.name)));
      entry.plan = planFor(entry.model);
      if (entry.model.names.length === 0) entry.plan.blocked = NO_NAMES_LEFT;
    }
  }

  // 7. The plan.
  const width = Math.max(0, ...entries.map((e) => e.model.cert.length));
  const support = supportFileChanges(config, discovery.supportIncludes);
  const tlsPlan = support.tls;
  const supportChanges = support.changes;
  if (tlsPlan.action === 'keep' && readText(TLS_CONF) !== undefined) out.warn(tlsPlan.warning);
  for (const w of discovery.warnings) out.warn(w.message, w.loc);

  let actions = 0;
  const history = loadState();
  for (const entry of entries) {
    const { model, plan } = entry;
    const name = model.cert.padEnd(width);
    let lines: string[];
    if (entry.failed) lines = [out.red(`failed: ${entry.failed}`)];
    else if (model.unused) lines = [out.dim(unusedMessage(model.cert))];
    else if (plan.blocked) lines = [out.yellow(`skipped: ${plan.blocked}`)];
    else if (plan.action === 'none' && plan.snippet === 'ok') lines = ['up to date'];
    else {
      lines = planLines(plan, model.deploy);
      const via = entry.dnsAccounts?.length ? entry.dnsAccounts.join(', ') : model.dnsAccount;
      if (plan.reason === 'new' && model.validation === 'dns') lines[0] = `${lines[0]} (DNS${via ? ` via ${via}` : ''})`;
      actions++;
    }
    for (const s of entry.skipped) lines.push(out.yellow(`skipped ${s.name}: ${s.reason}`));
    for (const w of entry.warnings) lines.push(out.yellow(`warning: ${w}`));
    for (const w of model.warnings) lines.push(out.yellow(`warning: ${w.loc ? `${formatLoc(w.loc)}: ` : ''}${w.message}`));
    for (const sk of model.skipped.filter((x) => x.warn || out.verbose)) {
      const text = `server_name ${JSON.stringify(sk.raw)} at ${formatLoc(sk)} skipped: ${sk.reason}`;
      lines.push(sk.warn ? out.yellow(`warning: ${text}`) : out.dim(text));
    }
    if (plan.action === 'issue' && !dryRun) {
      const recent = issuedWithin(history, model.cert, 7, now);
      if (recent >= 3) {
        lines.push(
          out.yellow(`warning: issued ${recent} times in the last 7 days; Let's Encrypt allows 5 per identical name set per week`),
        );
      }
    }
    const [first, ...rest] = lines;
    out.info(`${out.bold(name)}  ${first ?? ''}`);
    for (const line of rest) out.info(`${' '.repeat(width)}  ${line}`);
  }
  for (const change of supportChanges) out.info(change);
  actions += supportChanges.length;

  const work = entries.filter((e) => !e.failed && !e.model.unused && !e.plan.blocked && e.plan.action !== 'none');
  const snippetWork = entries.filter((e) => !e.model.unused && e.plan.snippet !== 'ok' && e.plan.snippet !== 'missing');
  if (work.length === 0 && snippetWork.length === 0 && supportChanges.length === 0 && created.changed.length === 0) {
    out.info(entries.length === 0 ? 'No certificates.' : 'Nothing to do.');
    return finish(ctx, entries, [], dryRun, now);
  }

  // 8. Confirm.
  if (actions > 0 && !(await ctx.prompt.confirm(dryRun ? 'Run these against the staging server (--dry-run)?' : 'Apply these changes?'))) {
    out.info('Nothing changed.');
    return 1;
  }

  // 9. certbot, per changed certificate.
  let busyNotice = -1;
  const runOptions = {
    onOutput: out.verbose ? (chunk: string) => void out.stdout.write(chunk) : undefined,
    onBusy: (waited: number) => {
      const minutes = Math.floor(waited / 60_000);
      if (minutes !== busyNotice) {
        busyNotice = minutes;
        out.info(`certbot is busy (another certbot, e.g. its renewal timer, holds its lock); waiting${minutes > 0 ? ` (${minutes} min)` : ''}…`);
      }
    },
  };
  for (const entry of work) {
    const cert = entry.model.cert;
    const certbotRun = async (plan: CertPlan, model: CertModel) => {
      const settings = issueSettings(model, config);
      const args =
        plan.action === 'reconfigure' && !dryRun
          ? reconfigureArgs(settings)
          : certonlyArgs(settings, { forceRenewal: plan.forceRenewal, dryRun });
      out.info(`${dryRun ? 'Testing' : plan.action === 'reconfigure' ? 'Reconfiguring' : 'Issuing'} ${cert}…`);
      return runCertbot(args, runOptions);
    };
    const reconfiguring = entry.plan.action === 'reconfigure' && !dryRun;
    let result = await certbotRun(entry.plan, entry.model);
    if (!result.ok && reconfiguring) {
      // Its test renewal failed: a production certonly with fewer names is not the answer.
      entry.failed = result.busy
        ? 'certbot was still busy after 30 minutes'
        : `certbot reconfigure's test renewal failed, so the renewal settings are unchanged:\n${failureSummary(result.output)}`;
      continue;
    }
    if (!result.ok && result.rejected.length > 0 && !options.strict) {
      // Let's Encrypt rejected some names: once more without them. The identifier x stands for x and *.x.
      const dropped = new Map<string, string>();
      for (const r of result.rejected) {
        for (const name of namesOfIdentifier(entry.model, r.name)) dropped.set(name, r.reason);
      }
      const core = [...dropped.keys()].filter((n) => coreNames(entry.model).has(n));
      if (core.length > 0) {
        entry.failed = `${cert} always contains ${entry.model.domain} and *.${entry.model.domain}, and Let's Encrypt rejected ${core.join(', ')}:\n${failureSummary(result.output)}`;
        continue;
      }
      if (dropped.size > 0) {
        for (const [name, reason] of dropped) entry.skipped.push({ name, reason, at: now.toISOString() });
        entry.model = withoutNames(entry.model, new Set(dropped.keys()));
        entry.plan = planFor(entry.model);
        out.warn(`${cert}: Let's Encrypt rejected ${[...dropped.keys()].join(', ')}; trying again without ${dropped.size > 1 ? 'them' : 'it'}`);
        if (entry.model.names.length === 0) {
          entry.failed = NO_NAMES_LEFT;
          continue;
        }
        if (entry.plan.blocked || entry.plan.action === 'none') continue;
        result = await certbotRun(entry.plan, entry.model);
      }
    }
    if (!result.ok) {
      entry.failed = result.busy
        ? 'certbot was still busy after 30 minutes'
        : `certbot failed:\n${failureSummary(result.output)}`;
      continue;
    }
    if (result.notDue && !dryRun) {
      entry.incomplete = true;
      out.warn(`${cert}: certbot kept the certificate ("not yet due for renewal"), so nothing changed`);
      continue;
    }
    if (entry.plan.action === 'reconfigure' && !dryRun) entry.reconfigured = true;
    else entry.issued = true;
  }

  // 10. The generated files.
  const batch = new FileBatch();
  if (!dryRun) {
    certbot = new Map(readCertbotCerts().map((c) => [c.name, c]));
    for (const entry of entries) {
      if (entry.model.snippetExists || entry.model.included) writeSnippet(batch, entry.model.cert, certbot.has(entry.model.cert));
    }
    if (tlsPlan.action === 'write') batch.write(TLS_CONF, tlsPlan.content, 0o644);
    else if (tlsPlan.action === 'remove') batch.remove(TLS_CONF);
    batch.write(ACME_CONF, acmeConfContent(config.webroot), 0o644);
  }

  // 11. nginx -t, reload, then the deploy commands of the issued certificates.
  const issued = entries.filter((e) => e.issued);
  const deployFailures: string[] = [];
  if (!dryRun && (batch.changed.length > 0 || created.changed.length > 0 || issued.length > 0)) {
    let nginxFailed = false;
    const after = await nginxTest(config);
    if (!after.ok) {
      batch.restore();
      out.error(`nginx -t failed with the new files, so the previous ones are back and nginx wasn't reloaded:\n${after.output}`);
      nginxFailed = true;
    } else if (options.reload === false) {
      out.info('nginx not reloaded (--no-reload).');
    } else {
      const reload = await nginxReload(config);
      if (reload.ok) out.info('Reloaded nginx.');
      else {
        out.error(`reloading nginx failed: ${reload.output}`);
        nginxFailed = true;
      }
    }
    // The certificates were issued either way: their deploy commands run, as in certbot's deploy hook.
    for (const entry of issued) {
      for (const command of entry.model.deploy) {
        const r = await runDeploy(command);
        if (!r.ok) deployFailures.push(`${entry.model.cert}: ${command}: ${r.output || 'failed'}`);
      }
    }
    if (nginxFailed) {
      finish(ctx, entries, deployFailures, dryRun, now);
      return 1;
    }
  }
  if (dryRun && created.changed.length > 0) {
    out.info(`Kept for nginx -t (--dry-run): ${created.changed.join(', ')}`);
  }

  // 12. State and summary.
  return finish(ctx, entries, deployFailures, dryRun, now);
}

function finish(ctx: Context, entries: Entry[], deployFailures: string[], dryRun: boolean, now: Date): number {
  const { out } = ctx;
  if (!dryRun) {
    const state = loadState();
    for (const entry of entries) {
      const s = certState(state, entry.model.cert);
      s.skipped = entry.skipped;
      if (entry.issued) recordIssued(state, entry.model.cert, now);
    }
    saveState(state);
  }
  const done = entries.filter((e) => e.issued || e.reconfigured);
  const failed = entries.filter((e) => e.failed);
  const skipped = entries.flatMap((e) => e.skipped.map((s) => `${e.model.cert}: ${s.name} (${s.reason})`));
  const empty = entries.filter((e) => !e.failed && !e.model.unused && e.plan.blocked);
  if (done.length > 0 || failed.length > 0) out.info();
  for (const e of done) {
    out.info(
      `${out.green('✓')} ${e.model.cert}: ${e.reconfigured ? 'renewal settings updated' : dryRun ? 'test issuance passed (--dry-run)' : `issued (${e.model.names.length} name${e.model.names.length === 1 ? '' : 's'})`}`,
    );
  }
  for (const e of failed) out.error(`${e.model.cert}: ${e.failed}`);
  for (const s of skipped) out.warn(`skipped ${s}`);
  for (const d of deployFailures) out.warn(`deploy command failed: ${d}`);
  const incomplete = entries.some((e) => e.incomplete);
  return failed.length > 0 || skipped.length > 0 || empty.length > 0 || deployFailures.length > 0 || incomplete ? 2 : 0;
}
