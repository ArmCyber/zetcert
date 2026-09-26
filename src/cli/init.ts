// `zetcert init`: installs or upgrades the system copy, creates the config, and
// writes the support files, the placeholder certificate and the certbot hooks. Safe to run again.
import { chmodSync } from 'node:fs';
import { isIP } from 'node:net';
import path from 'node:path';
import { type CertbotVersion, certbotVersion, readCertFile, versionAtLeast } from '../certbot/reader';
import { type Config, isSafePath, loadConfig, parseConfig } from '../config/config';
import { configTemplate } from '../config/template';
import { discover, type Discovery } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { PLACEHOLDER_CERT, PLACEHOLDER_KEY } from '../nginx/snippets';
import { ACME_CONF, acmeConfContent, DHPARAM_FILE, FFDHE2048_PEM, TLS_CONF, tlsFilePlan } from '../nginx/support';
import { localPublicIps } from '../precheck/ips';
import { UserError } from '../system/errors';
import { exec, type ExecResult, shell } from '../system/exec';
import { FileBatch } from '../system/files';
import { ensureDir, exists, readText, writeFileAtomic } from '../system/fs';
import {
  copyNewBundle,
  DEPLOY_HOOK,
  hookScript,
  installSystemCopy,
  pendingUpgrade,
  POST_HOOK,
  SYSTEM_BUNDLE,
  SYSTEM_NODE,
} from '../system/install';
import { DNS_DIR, LAUNCHER, onDisk, PLACEHOLDER_DIR, SNIPPET_DIR, STATE_FILE } from '../system/paths';
import { acquireLock } from '../system/lock';
import { isRoot } from '../system/root';
import { VERSION } from '../version';
import { importLocked, notImported } from './import';
import type { Context } from './program';
import { PLAIN_DEPLOY_HOOK, PLAIN_HOOK_MARKER } from './uninstall';

export interface InitEnv {
  /** Real path of the running bundle. */
  bundle: string;
  /** Real path of the Node binary running it. */
  node: string;
  /** The arguments after `zetcert`, to run init again with sudo or from a new copy. */
  argv: string[];
  /** Tests only: the uid that counts as root for file ownership. */
  rootUid?: number;
}

interface Tools {
  certbot: CertbotVersion;
  nginx: string;
  nginxConfig: string;
  openssl: string;
}

/** The main config path from `nginx -V`: --conf-path, else <prefix>/conf/nginx.conf. */
export function nginxConfPath(nginxV: string): string {
  const prefix = /--prefix=(\S+)/.exec(nginxV)?.[1] ?? '/usr/local/nginx';
  const conf = /--conf-path=(\S+)/.exec(nginxV)?.[1] ?? 'conf/nginx.conf';
  return path.resolve(prefix, conf);
}

async function tryExec(command: string, args: string[]): Promise<ExecResult | undefined> {
  try {
    return await exec(command, args, { timeoutMs: 60_000 });
  } catch {
    return undefined;
  }
}

async function checkTools(): Promise<Tools> {
  const certbot = await certbotVersion();
  const nginx = await tryExec('nginx', ['-V']);
  const openssl = await tryExec('openssl', ['version']);
  const missing = [
    ...(certbot ? [] : ['certbot (apt install certbot, or the snap)']),
    ...(nginx?.code === 0 ? [] : ['nginx']),
    ...(openssl?.code === 0 ? [] : ['openssl']),
  ];
  if (!certbot || !nginx || nginx.code !== 0 || !openssl || openssl.code !== 0) {
    throw new UserError(`zetcert needs ${missing.join(', ')}: install ${missing.length > 1 ? 'them' : 'it'} and run zetcert init again`);
  }
  if (!versionAtLeast(certbot, 1, 21)) {
    throw new UserError(`certbot ${certbot.text} is too old: zetcert needs certbot 1.21 or newer`);
  }
  const nginxText = `${nginx.stdout}\n${nginx.stderr}`;
  return {
    certbot,
    nginx: /nginx\/(\S+)/.exec(nginxText)?.[1] ?? 'unknown version',
    nginxConfig: nginxConfPath(nginxText),
    openssl: openssl.stdout.trim(),
  };
}

async function askValid(
  ctx: Context,
  question: string,
  defaultValue: string,
  check: (answer: string) => string | undefined,
): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const answer = (await ctx.prompt.ask(question, defaultValue)).trim();
    const problem = check(answer);
    if (!problem) return answer;
    ctx.out.warn(problem);
  }
  throw new UserError(`${question.replace(/:$/, '')}: no valid answer`);
}

const splitList = (text: string) => text.split(/[\s,]+/).filter(Boolean);

async function createConfig(ctx: Context, nginxConfig: string): Promise<void> {
  const email = await askValid(ctx, "Email for the Let's Encrypt account (optional):", '', (v) =>
    v === '' || /^[^\s@]+@[^\s@]+$/.test(v) ? undefined : `not an email address: ${v}`,
  );
  const webroot = await askValid(ctx, 'Webroot that port 80 serves /.well-known/acme-challenge/ from:', '/var/www/html', (v) =>
    isSafePath(v) ? undefined : 'the webroot must be an absolute path without spaces or quotes',
  );
  const ips = await askValid(ctx, "This server's public IP addresses, separated by commas (for the pre-checks):", localPublicIps().join(', '), (v) => {
    const bad = splitList(v).filter((ip) => isIP(ip) === 0);
    return bad.length === 0 ? undefined : `not an IP address: ${bad.join(', ')}`;
  });
  const notify = await ctx.prompt.ask('Command that gets alerts on stdin (optional):', '');
  const text = configTemplate({ email: email || undefined, webroot, publicIps: splitList(ips), notify: notify.trim(), nginxConfig });
  parseConfig(text, ctx.configPath);
  ensureDir(path.dirname(ctx.configPath), 0o755);
  writeFileAtomic(ctx.configPath, text, 0o600);
}

async function ensurePlaceholder(): Promise<boolean> {
  try {
    if (readCertFile(PLACEHOLDER_CERT) && exists(PLACEHOLDER_KEY)) return false;
  } catch {
    // unreadable: make a new one
  }
  ensureDir(PLACEHOLDER_DIR, 0o755);
  const r = await exec(
    'openssl',
    [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '36500',
      '-subj', '/CN=zetcert placeholder',
      '-keyout', onDisk(PLACEHOLDER_KEY), '-out', onDisk(PLACEHOLDER_CERT),
    ],
    { timeoutMs: 120_000 },
  );
  if (r.code !== 0) throw new UserError(`openssl couldn't create the placeholder certificate: ${r.stderr.trim()}`);
  chmodSync(onDisk(PLACEHOLDER_KEY), 0o600);
  chmodSync(onDisk(PLACEHOLDER_CERT), 0o644);
  return true;
}

function nginxDiscovery(config: Config): Discovery | undefined {
  try {
    return discover(loadNginxConfig(config.nginx.config));
  } catch {
    return undefined;
  }
}

/** Writes _tls.conf, _ffdhe2048.pem and _acme.conf; returns warnings. */
export function writeSupportFiles(batch: FileBatch, config: Config, discovery: Discovery | undefined): string[] {
  const warnings: string[] = [];
  ensureDir(SNIPPET_DIR, 0o755);
  batch.write(DHPARAM_FILE, FFDHE2048_PEM, 0o644);
  batch.write(ACME_CONF, acmeConfContent(config.webroot), 0o644);
  const plan = tlsFilePlan(config.tls, discovery?.supportIncludes);
  if (plan.action === 'write') batch.write(TLS_CONF, plan.content, 0o644);
  else if (plan.action === 'remove') batch.remove(TLS_CONF);
  else if (exists(TLS_CONF)) warnings.push(plan.warning);
  return warnings;
}

export async function init(ctx: Context, env: InitEnv): Promise<number> {
  const { out } = ctx;
  if (!isRoot()) {
    out.info('zetcert init needs root: running it again with sudo.');
    const r = await exec('sudo', [env.node, env.bundle, ...env.argv], { interactive: true });
    return r.code ?? 1;
  }

  const upgrade = pendingUpgrade(env.bundle, VERSION);
  if (upgrade) {
    out.info(`Upgrading the system copy from ${VERSION} to ${upgrade.version} (from ${upgrade.npm}).`);
    copyNewBundle(upgrade.npm);
    const r = await exec(onDisk(SYSTEM_NODE), [onDisk(SYSTEM_BUNDLE), ...env.argv], { interactive: true });
    return r.code ?? 1;
  }

  const tools = await checkTools();
  out.info(`certbot ${tools.certbot.text} · nginx ${tools.nginx} · ${tools.openssl}`);
  const lock = acquireLock();
  try {
    return await installAll(ctx, env, tools);
  } finally {
    lock.release();
  }
}

async function installAll(ctx: Context, env: InitEnv, tools: Tools): Promise<number> {
  const { out } = ctx;

  const installed = installSystemCopy({ bundle: env.bundle, node: env.node, version: VERSION, rootUid: env.rootUid });
  if (installed.upgradedFrom) out.info(`Upgraded the system copy from ${installed.upgradedFrom} to ${VERSION}.`);
  else out.info(`${installed.firstInstall ? 'Installed' : 'Refreshed'} zetcert ${VERSION} in ${path.dirname(SYSTEM_BUNDLE)}: sudo zetcert runs it through ${LAUNCHER}.`);
  if (!installed.nodeLinked) {
    const why = installed.nodeFromSnap ? "a snap's path changes when it updates" : "it isn't owned and writable only by root";
    out.info(`Node: copied ${env.node} into ${SYSTEM_NODE}, because ${why}.`);
  }

  if (!exists(ctx.configPath)) {
    await createConfig(ctx, tools.nginxConfig);
    out.info(`Created ${ctx.configPath}.`);
  }
  const config = loadConfig(ctx.configPath).config;
  ensureDir(DNS_DIR, 0o700);
  ensureDir(path.dirname(STATE_FILE), 0o755);

  const batch = new FileBatch();
  const previousTls = readText(TLS_CONF);
  const previousAcme = readText(ACME_CONF);
  for (const warning of writeSupportFiles(batch, config, nginxDiscovery(config))) out.warn(warning);
  if (batch.changed.length > 0) out.info(`Wrote ${batch.changed.map((f) => path.basename(f)).join(', ')} in ${SNIPPET_DIR}.`);

  if (await ensurePlaceholder()) out.info(`Created the placeholder certificate in ${PLACEHOLDER_DIR}.`);

  const hooks = new FileBatch();
  ensureDir(path.dirname(DEPLOY_HOOK), 0o755);
  ensureDir(path.dirname(POST_HOOK), 0o755);
  hooks.write(DEPLOY_HOOK, hookScript('deploy'), 0o755);
  hooks.write(POST_HOOK, hookScript('post'), 0o755);
  // The plain hook an earlier uninstall left would reload nginx a second time, even during sync.
  if (readText(PLAIN_DEPLOY_HOOK)?.includes(PLAIN_HOOK_MARKER)) {
    hooks.remove(PLAIN_DEPLOY_HOOK);
    out.info(`Removed ${PLAIN_DEPLOY_HOOK}, left by an earlier uninstall.`);
  }
  if (hooks.changed.length > 0) out.info(`Installed the certbot hooks ${DEPLOY_HOOK} and ${POST_HOOK}.`);

  // Changed settings in files nginx may already use: reload, after nginx -t.
  const changedInUse =
    (previousTls !== undefined && readText(TLS_CONF) !== previousTls) ||
    (previousAcme !== undefined && readText(ACME_CONF) !== previousAcme);
  if (changedInUse) {
    const test = await shell(config.nginx.test, { timeoutMs: 120_000 });
    if (test.code !== 0) {
      batch.restore();
      throw new UserError(`nginx -t failed with the new files, so the previous ones are back:\n${(test.stdout + test.stderr).trim()}`);
    }
    const reload = await shell(config.nginx.reload, { timeoutMs: 120_000 });
    if (reload.code !== 0) throw new UserError(`reloading nginx failed: ${(reload.stdout + reload.stderr).trim()}`);
    out.info('Reloaded nginx.');
  }

  const importable = notImported();
  if (importable.length > 0) {
    out.info();
    if (await ctx.prompt.confirm(`certbot has certificates zetcert doesn't manage yet: ${importable.join(', ')}. Import them?`)) {
      await importLocked(ctx, importable, {});
    }
  }

  if (installed.firstInstall) {
    out.info();
    out.info('Next:');
    out.info('  1. In each HTTPS server block, include its certificate: include /etc/nginx/zetcert/<cert>.conf;');
    out.info(`  2. Port 80 must serve /.well-known/acme-challenge/ from ${config.webroot}: include ${ACME_CONF}; does that.`);
    out.info(`  3. Optional: include ${TLS_CONF}; once in http {} (remove Debian's ssl_protocols and ssl_prefer_server_ciphers).`);
    out.info('  4. sudo zetcert sync');
  }
  return 0;
}
