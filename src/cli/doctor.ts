// `zetcert doctor`: a full health check of the install, certbot, nginx, HTTP and DNS
// validation, and the certificates nginx serves.
import { statSync } from 'node:fs';
import { certbotVersion, readAccounts, readCertbotCerts } from '../certbot/reader';
import { certHealth, isoDay } from '../certs/health';
import { planCert } from '../certs/planner';
import { buildModel, type CertModel } from '../certs/model';
import { type Config, loadConfig } from '../config/config';
import { loadDnsAccountsSafe } from '../config/dns-accounts';
import { driverFor } from '../dns/index';
import { ZoneFinder } from '../dns/zones';
import { type Discovery, discover } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { checkServed, servedTargets } from '../nginx/served';
import { existingSnippets, usesPlaceholder } from '../nginx/snippets';
import { checkAddresses, checkCaa, checkHttp } from '../precheck/checks';
import { localPublicIps } from '../precheck/ips';
import { systemLookup } from '../precheck/lookup';
import { exec } from '../system/exec';
import { exists, isDirectory, readText } from '../system/fs';
import {
  compareVersions,
  DEPLOY_HOOK,
  hookScript,
  notRootOnly,
  npmVersion,
  POST_HOOK,
  readInstallInfo,
  SYSTEM_BUNDLE,
  SYSTEM_NODE,
} from '../system/install';
import { formatLoc } from '../system/loc';
import { LAUNCHER, onDisk } from '../system/paths';
import { isRoot } from '../system/root';
import { loadState, saveState } from '../system/state';
import { readSnippet } from './load';
import { nginxTest } from './nginx';
import type { Output } from './output';
import type { Context } from './program';

type Level = 'ok' | 'warn' | 'fail';

class Report {
  problems = 0;
  warnings = 0;

  constructor(private readonly out: Output) {}

  section(title: string): void {
    this.out.info();
    this.out.info(this.out.bold(title));
  }

  line(level: Level, text: string): void {
    const mark = level === 'ok' ? this.out.green('✓') : level === 'warn' ? this.out.yellow('!') : this.out.red('✗');
    if (level === 'fail') this.problems++;
    if (level === 'warn') this.warnings++;
    const [first, ...rest] = text.split('\n');
    this.out.info(`  ${mark} ${first}`);
    for (const l of rest) this.out.info(`    ${l}`);
  }
}

async function tryExec(command: string, args: string[]) {
  try {
    return await exec(command, args, { timeoutMs: 60_000 });
  } catch {
    return undefined;
  }
}

async function checkInstall(r: Report): Promise<void> {
  r.section('The install');
  r.line(isRoot() ? 'ok' : 'fail', isRoot() ? 'running as root' : 'not running as root: sudo zetcert doctor');
  const info = readInstallInfo();
  if (!info) {
    r.line('fail', `no system copy in ${SYSTEM_BUNDLE}: run zetcert init`);
    return;
  }
  const npm = info.npm ? npmVersion(info.npm) : undefined;
  if (!info.npm) r.line('ok', `system copy ${info.version}`);
  else if (npm === undefined) {
    r.line('warn', `system copy ${info.version}, but the npm copy at ${info.npm} is gone: upgrades come from there (npm install -g zetcert, then zetcert init)`);
  } else if (compareVersions(npm, info.version) > 0) {
    r.line('warn', `npm has zetcert ${npm}, but the system copy is ${info.version}: run sudo zetcert init to upgrade it`);
  } else if (compareVersions(npm, info.version) < 0) {
    r.line('warn', `the npm copy (${npm}) is older than the system copy (${info.version}): upgrades come from the npm copy`);
  } else {
    r.line('ok', `system copy ${info.version}, the same version as the npm copy`);
  }
  const version = await tryExec('env', ['-i', LAUNCHER, '--version']);
  const works = version?.code === 0 && version.stdout.trim() === info.version;
  r.line(
    works ? 'ok' : 'fail',
    works
      ? `env -i ${LAUNCHER} --version works`
      : `env -i ${LAUNCHER} --version fails: ${(version?.stderr || version?.stdout || 'not found').trim()}; run zetcert init`,
  );
  for (const file of [LAUNCHER, SYSTEM_BUNDLE, SYSTEM_NODE, DEPLOY_HOOK, POST_HOOK]) {
    if (!exists(file)) continue;
    const bad = notRootOnly(file);
    r.line(
      bad ? 'fail' : 'ok',
      bad
        ? `${file}: ${bad} isn't owned by root, or others than root can write it; another user could get root at the next renewal`
        : `${file} and the directories above it are root-only`,
    );
  }
}

async function checkCertbot(r: Report): Promise<void> {
  r.section('certbot');
  const version = await certbotVersion();
  r.line(version ? 'ok' : 'fail', version ? `certbot ${version.text}` : 'certbot is not installed');
  let timer: string | undefined;
  for (const unit of ['certbot.timer', 'snap.certbot.renew.timer']) {
    const active = await tryExec('systemctl', ['is-active', unit]);
    if (active?.code === 0) timer = unit;
  }
  r.line(timer ? 'ok' : 'fail', timer ? `${timer} is active` : 'no active certbot timer (certbot.timer or snap.certbot.renew.timer): nothing renews');
  for (const [file, kind] of [
    [DEPLOY_HOOK, 'deploy'],
    [POST_HOOK, 'post'],
  ] as const) {
    const content = readText(file);
    // certbot skips hook files it can't execute, without a word.
    const executable = content !== undefined && (statSync(onDisk(file)).mode & 0o111) !== 0;
    if (content === undefined) r.line('fail', `${file} is missing: run zetcert init`);
    else if (content !== hookScript(kind)) r.line('fail', `${file} was changed: run zetcert init`);
    else if (!executable) r.line('fail', `${file} isn't executable, so certbot skips it: run zetcert init`);
    else r.line('ok', `${file} is installed`);
  }
  const openssl = await tryExec('openssl', ['version']);
  r.line(openssl?.code === 0 ? 'ok' : 'fail', openssl?.code === 0 ? openssl.stdout.trim() : 'openssl is not installed');
}

async function checkNginx(r: Report, config: Config): Promise<Discovery | undefined> {
  r.section('nginx');
  const test = await nginxTest(config);
  r.line(test.ok ? 'ok' : 'fail', test.ok ? `${config.nginx.test} passes` : `${config.nginx.test} fails:\n${test.output}`);
  let discovery: Discovery;
  try {
    discovery = discover(loadNginxConfig(config.nginx.config));
  } catch (err) {
    r.line('fail', `the nginx config can't be read: ${(err as Error).message}`);
    return undefined;
  }
  const warnings = [
    ...discovery.errors.map((e) => `${formatLoc(e.loc)}: ${e.message}`),
    ...discovery.warnings.map((w) => `${formatLoc(w.loc)}: ${w.message}`),
    ...discovery.missing.map((m) => `${formatLoc(m)}: the included file ${m.path} doesn't exist`),
    ...discovery.skipped.filter((s) => s.warn).map((s) => `${formatLoc(s)}: server_name ${JSON.stringify(s.raw)} skipped: ${s.reason}`),
  ];
  if (warnings.length === 0) r.line('ok', 'no parse warnings');
  for (const w of warnings) r.line('warn', w);
  for (const loc of discovery.stapling) {
    r.line('warn', `${formatLoc(loc)}: ssl_stapling on is useless: Let's Encrypt ended OCSP in 2025`);
  }
  return discovery;
}

async function checkHttpValidation(r: Report, config: Config, models: CertModel[]): Promise<void> {
  r.section('HTTP validation');
  r.line(isDirectory(config.webroot) ? 'ok' : 'fail', isDirectory(config.webroot) ? `the webroot ${config.webroot} exists` : `the webroot ${config.webroot} doesn't exist`);
  const names = [...new Set(models.filter((m) => m.validation === 'http' && !m.unused).flatMap((m) => m.names.map((n) => n.name)))];
  if (names.length === 0) {
    r.line('ok', 'no HTTP-validated names');
    return;
  }
  const lookup = systemLookup();
  const publicIps = [...new Set([...config.public_ips, ...localPublicIps()])];
  const accounts = [...readAccounts().values()];
  for (const name of names) {
    const results = [
      await checkHttp(name, config.webroot, config.precheck.http_address),
      await checkAddresses(name, publicIps, lookup),
      await checkCaa(name, 'http-01', accounts, lookup),
    ];
    const failed = results.filter((x) => !x.ok);
    const warnings = results.flatMap((x) => x.warnings);
    if (failed.length > 0) r.line('fail', `${name}: ${failed.map((x) => x.reason).join('; ')}`);
    else if (warnings.length > 0) r.line('warn', `${name}: ${warnings.join('; ')}`);
    else r.line('ok', `${name}: nginx serves the ACME path, DNS points here, CAA allows Let's Encrypt`);
  }
}

async function checkDns(r: Report, models: CertModel[]): Promise<void> {
  r.section('DNS accounts');
  const { accounts, problems } = loadDnsAccountsSafe();
  for (const problem of problems) r.line('fail', problem);
  const dnsModels = models.filter((m) => m.validation === 'dns' && !m.unused);
  if (accounts.length === 0 && problems.length === 0 && dnsModels.length === 0) {
    r.line('ok', 'none, and no certificate needs one');
    return;
  }
  for (const account of accounts) {
    try {
      await driverFor(account).verify();
      r.line('ok', `${account.name} (${account.driver}): the credentials work`);
    } catch (err) {
      r.line('fail', `${account.name} (${account.driver}): ${(err as Error).message}`);
    }
  }
  const state = loadState();
  const finder = new ZoneFinder(accounts, state, driverFor);
  const lookup = systemLookup();
  const uris = [...readAccounts().values()];
  for (const model of dnsModels) {
    for (const { name } of model.names) {
      try {
        const match = await finder.find(name, model.dnsAccount);
        const caa = await checkCaa(name, 'dns-01', uris, lookup);
        if (!match) r.line('fail', `${model.cert}: no DNS account manages ${name}`);
        else if (!caa.ok) r.line('fail', `${model.cert}: ${name}: ${caa.reason}`);
        else r.line('ok', `${model.cert}: ${name} is in ${match.zone.name} (${match.account.name})`);
      } catch (err) {
        r.line('fail', `${model.cert}: ${name}: ${(err as Error).message}`);
      }
    }
  }
  saveState(state);
}

async function checkCertificates(r: Report, config: Config, models: CertModel[]): Promise<void> {
  r.section('Certificates');
  const certbot = new Map(readCertbotCerts().map((c) => [c.name, c]));
  const version = await certbotVersion();
  const state = loadState();
  if (models.length === 0) r.line('ok', 'no certificates yet');
  for (const model of models) {
    const actual = certbot.get(model.cert);
    const snippet = readSnippet(model.cert);
    const plan = planCert({ model, actual, snippet, webroot: config.webroot, certbotVersion: version });
    const findings = certHealth({ model, plan, actual, placeholder: usesPlaceholder(snippet), skipped: state.certs[model.cert]?.skipped ?? [], now: new Date() });
    for (const f of findings) {
      r.line(f.severity === 'critical' ? 'fail' : f.severity === 'warning' ? 'warn' : 'ok', `${model.cert}: ${f.message}`);
    }
    if (findings.length === 0) {
      r.line('ok', `${model.cert}: up to date${actual?.cert ? `, expires ${isoDay(actual.cert.notAfter)}` : ''}`);
    }
  }
}

async function checkServedCerts(r: Report, discovery: Discovery): Promise<void> {
  r.section('Certificates nginx serves');
  const results = await checkServed(servedTargets(discovery, readSnippet));
  if (results.length === 0) r.line('ok', 'no listen … ssl blocks use zetcert certificates');
  for (const x of results) {
    const where = `${x.name} on ${x.address} (${formatLoc(x.listen)})`;
    if (x.status === 'ok') r.line('ok', `${where}: ${x.cert}`);
    else if (x.status === 'error') r.line('fail', `${where}: can't check: ${x.error}`);
    else if (x.status === 'no-file') r.line('fail', `${where}: the snippet or its certificate file is missing: run zetcert sync`);
    else r.line('fail', `${where}: nginx serves another certificate than ${x.expectedPath ?? x.cert}: reload nginx, or check the include`);
  }
}

export async function doctor(ctx: Context): Promise<number> {
  const { out } = ctx;
  const r = new Report(out);
  if (!ctx.initialized) out.warn(`zetcert init hasn't run yet: using the default settings (${ctx.configPath} doesn't exist)`);
  const config = loadConfig(ctx.configPath).config;
  await checkInstall(r);
  await checkCertbot(r);
  const discovery = await checkNginx(r, config);
  const models = discovery ? buildModel({ config, discovery, snippets: existingSnippets() }) : [];
  await checkHttpValidation(r, config, models);
  await checkDns(r, models);
  await checkCertificates(r, config, models);
  if (discovery) await checkServedCerts(r, discovery);
  out.info();
  out.info(
    r.problems > 0
      ? out.red(`${r.problems} problem${r.problems === 1 ? '' : 's'}${r.warnings > 0 ? `, ${r.warnings} warning${r.warnings === 1 ? '' : 's'}` : ''}.`)
      : r.warnings > 0
        ? out.yellow(`No problems, ${r.warnings} warning${r.warnings === 1 ? '' : 's'}.`)
        : out.green('No problems.'),
  );
  return r.problems > 0 ? 1 : 0;
}
