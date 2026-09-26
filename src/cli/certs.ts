// `zetcert create <cert>`, `update <cert>` and `delete <cert>`.
import { deleteArgs } from '../certbot/commands';
import { failureSummary } from '../certbot/errors';
import { readCertbotCert } from '../certbot/reader';
import { runCertbot } from '../certbot/runner';
import { normalizeCertName } from '../certs/names';
import { CHALLENGES, KEY_TYPES, loadConfig } from '../config/config';
import { loadDnsAccount } from '../config/dns-accounts';
import { ConfigEditor } from '../config/editor';
import { isValidName, NAME_RULE } from '../config/names';
import { discover } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { existingSnippets, snippetPath, writeSnippet } from '../nginx/snippets';
import { UserError } from '../system/errors';
import { FileBatch } from '../system/files';
import { formatLoc } from '../system/loc';
import { acquireLock } from '../system/lock';
import { loadState, saveState } from '../system/state';
import type { Context } from './program';

export interface CertOptions {
  add?: string[];
  remove?: string[];
  exclude?: string[];
  unexclude?: string[];
  challenge?: string;
  dns?: string;
  keyType?: string;
  /** Commands to add; false with --no-deploy. */
  deploy?: string[] | false;
}

function name(value: string): string {
  const normalized = normalizeCertName(value);
  if (!normalized) throw new UserError(`not a valid DNS name: ${value}`);
  return normalized;
}

/** Applies the options to the certificate's config entry; returns what changed, for the output. */
function apply(ctx: Context, editor: ConfigEditor, cert: string, options: CertOptions): string[] {
  const keys = (key: string) => ['certs', cert, key];
  const changes: string[] = [];
  for (const n of options.add ?? []) {
    editor.addToList(keys('names'), name(n));
    changes.push(`+ name ${name(n)}`);
  }
  for (const n of options.remove ?? []) {
    editor.removeFromList(keys('names'), name(n));
    changes.push(`- name ${name(n)}`);
  }
  for (const n of options.exclude ?? []) {
    editor.addToList(keys('exclude'), name(n));
    changes.push(`+ exclude ${name(n)}`);
  }
  for (const n of options.unexclude ?? []) {
    editor.removeFromList(keys('exclude'), name(n));
    changes.push(`- exclude ${name(n)}`);
  }
  if (options.challenge !== undefined) {
    if (!(CHALLENGES as readonly string[]).includes(options.challenge)) throw new UserError('--challenge must be auto, http or dns');
    if (options.challenge === 'auto') editor.delete(keys('challenge'));
    else editor.set(keys('challenge'), options.challenge);
    changes.push(`challenge ${options.challenge}`);
  }
  if (options.dns !== undefined) {
    if (!isValidName(options.dns)) throw new UserError(`invalid DNS account name: account names ${NAME_RULE}`);
    if (!loadDnsAccount(options.dns)) ctx.out.warn(`there's no DNS account ${options.dns} yet: zetcert dns add ${options.dns} --driver …`);
    editor.set(keys('dns'), options.dns);
    changes.push(`DNS account ${options.dns}`);
  }
  if (options.keyType !== undefined) {
    if (!(KEY_TYPES as readonly string[]).includes(options.keyType)) throw new UserError('--key-type must be ecdsa or rsa');
    editor.set(keys('key_type'), options.keyType);
    changes.push(`key type ${options.keyType}`);
  }
  if (options.deploy === false) {
    editor.delete(keys('deploy'));
    changes.push('no deploy commands');
  } else {
    for (const command of options.deploy ?? []) {
      if (!command.trim()) throw new UserError('--deploy needs a command');
      editor.addToList(keys('deploy'), command.trim());
      changes.push(`+ deploy ${command.trim()}`);
    }
  }
  return changes;
}

function includedInNginx(nginxConfig: string, cert: string): boolean {
  try {
    return discover(loadNginxConfig(nginxConfig)).snippetIncludes.some((s) => s.cert === cert);
  } catch {
    return false;
  }
}

function isManaged(configCerts: Record<string, unknown>, cert: string): boolean {
  return cert in configCerts || existingSnippets().includes(cert);
}

export async function create(ctx: Context, cert: string, options: CertOptions): Promise<number> {
  const lock = acquireLock();
  try {
    if (!isValidName(cert)) throw new UserError(`invalid certificate name: certificate names ${NAME_RULE}`);
    const loaded = loadConfig(ctx.configPath);
    if (isManaged(loaded.config.certs, cert)) throw new UserError(`the certificate ${cert} exists: change it with zetcert update ${cert}`);
    const editor = new ConfigEditor(loaded);
    editor.keep.add(cert);
    editor.ensureMap(['certs', cert]);
    apply(ctx, editor, cert, options);
    editor.save();
    writeSnippet(new FileBatch(), cert, readCertbotCert(cert) !== undefined);
    ctx.out.info(`Created the certificate ${cert} and its snippet ${snippetPath(cert)}.`);
    ctx.out.info(`Include it in its server blocks (include ${snippetPath(cert)};), then run sudo zetcert sync.`);
    return 0;
  } finally {
    lock.release();
  }
}

export async function update(ctx: Context, cert: string, options: CertOptions): Promise<number> {
  const lock = acquireLock();
  try {
    const loaded = loadConfig(ctx.configPath);
    const editor = new ConfigEditor(loaded);
    if (!isManaged(loaded.config.certs, cert) && !includedInNginx(loaded.config.nginx.config, cert)) {
      throw new UserError(`no certificate named ${cert}: zetcert create ${cert} registers one`);
    }
    const changes = apply(ctx, editor, cert, options);
    if (changes.length === 0) throw new UserError('nothing to change: see zetcert update --help');
    editor.save();
    ctx.out.info(`${cert}: ${changes.join(', ')}.`);
    ctx.out.info('The next sync applies the changes: sudo zetcert sync');
    return 0;
  } finally {
    lock.release();
  }
}

export interface DeleteOptions {
  force?: boolean;
  keepCert?: boolean;
}

export async function deleteCert(ctx: Context, cert: string, options: DeleteOptions): Promise<number> {
  const lock = acquireLock();
  try {
    const { out } = ctx;
    const loaded = loadConfig(ctx.configPath);
    let includes;
    try {
      includes = discover(loadNginxConfig(loaded.config.nginx.config)).snippetIncludes.filter((s) => s.cert === cert);
    } catch (err) {
      throw new UserError(`can't read the nginx config to check whether it still uses ${cert}: ${(err as Error).message}`);
    }
    const inCertbot = readCertbotCert(cert) !== undefined;
    if (!isManaged(loaded.config.certs, cert) && includes.length === 0) {
      throw new UserError(
        inCertbot
          ? `zetcert doesn't manage ${cert}: to delete certbot's certificate, use certbot delete --cert-name ${cert}`
          : `no certificate named ${cert}`,
      );
    }
    if (includes.length > 0 && !options.force) {
      throw new UserError(
        `nginx still includes ${cert} (${includes.map((i) => formatLoc(i)).join(', ')}): remove the includes and reload nginx first, or use --force (the snippet then stays and points at the placeholder)`,
      );
    }

    const steps = [
      ...(inCertbot && !options.keepCert ? [`delete the certificate from certbot (certbot delete --cert-name ${cert})`] : []),
      includes.length > 0 ? `point ${snippetPath(cert)} at the placeholder, because nginx still includes it` : `remove ${snippetPath(cert)}`,
      ...(cert in loaded.config.certs ? [`remove certs.${cert} from ${ctx.configPath}`] : []),
    ];
    out.info(`Deleting ${cert} will:`);
    for (const step of steps) out.info(`  - ${step}`);
    if (!(await ctx.prompt.confirm(`Delete ${cert}?`, true))) {
      out.info('Nothing changed.');
      return 1;
    }

    const files = new FileBatch();
    // First the placeholder, so nginx -t keeps passing once certbot's files are gone.
    if (includes.length > 0) writeSnippet(files, cert, false);
    if (inCertbot && !options.keepCert) {
      const r = await runCertbot(deleteArgs(cert), {
        onBusy: (waited) => out.info(`certbot is busy (e.g. its renewal timer); waiting (${Math.floor(waited / 60_000)} min)…`),
      });
      if (!r.ok) throw new UserError(`certbot delete failed:\n${failureSummary(r.output)}`);
    }
    if (includes.length === 0) files.remove(snippetPath(cert));
    if (cert in loaded.config.certs) {
      const editor = new ConfigEditor(loaded);
      editor.delete(['certs', cert]);
      editor.save();
    }
    const state = loadState();
    delete state.certs[cert];
    delete state.alerts[cert];
    saveState(state);
    out.info(`Deleted ${cert}.`);
    return 0;
  } finally {
    lock.release();
  }
}
