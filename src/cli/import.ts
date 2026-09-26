// `zetcert import <name…>` / `import --all`: takes over certificates certbot already has.
// Nothing is issued: the next sync applies zetcert's renewal settings.
import { readCertbotCerts } from '../certbot/reader';
import { buildModel } from '../certs/model';
import { loadConfig } from '../config/config';
import { ConfigEditor } from '../config/editor';
import { isValidName, NAME_RULE } from '../config/names';
import { discover, type Discovery } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { existingSnippets, snippetPath, writeSnippet } from '../nginx/snippets';
import { UserError } from '../system/errors';
import { FileBatch } from '../system/files';
import { acquireLock } from '../system/lock';
import type { Context } from './program';

export interface ImportOptions {
  all?: boolean;
}

/** certbot's certificates that have no snippet yet. */
export function notImported(): string[] {
  const snippets = new Set(existingSnippets());
  return readCertbotCerts()
    .map((c) => c.name)
    .filter((name) => !snippets.has(name));
}

export async function importCerts(ctx: Context, names: string[], options: ImportOptions): Promise<number> {
  const lock = acquireLock();
  try {
    return await importLocked(ctx, names, options);
  } finally {
    lock.release();
  }
}

/** import, for a caller that already holds the lock (init). */
export async function importLocked(ctx: Context, names: string[], options: ImportOptions): Promise<number> {
  const { out } = ctx;
  const certbot = new Map(readCertbotCerts().map((c) => [c.name, c]));
  if (!options.all && names.length === 0) throw new UserError('name the certificates to import, or use --all');
  const targets = options.all ? [...certbot.keys()] : names;
  if (targets.length === 0) {
    out.info("certbot has no certificates.");
    return 0;
  }

  const problems: string[] = [];
  const editor = new ConfigEditor(loadConfig(ctx.configPath));
  const batch = new FileBatch();
  const imported: string[] = [];
  for (const name of targets) {
    const cert = certbot.get(name);
    if (!cert) {
      problems.push(`certbot has no certificate named ${name}`);
      continue;
    }
    if (!isValidName(name)) {
      problems.push(`${name} can't be imported: certificate names ${NAME_RULE}`);
      continue;
    }
    writeSnippet(batch, name, true);
    imported.push(name);
    const hooks = cert.renewal;
    if (hooks.deployHook) {
      editor.addToList(['certs', name, 'deploy'], hooks.deployHook);
      out.info(`${name}: moved certbot's deploy hook into its deploy list: ${hooks.deployHook}`);
    }
    for (const [kind, command] of [['pre', hooks.preHook], ['post', hooks.postHook]] as const) {
      if (command) {
        out.warn(`${name}: certbot's ${kind} hook "${command}" isn't used by zetcert; the next sync removes it from certbot`);
      }
    }
  }
  const saved = editor.save();

  let discovery: Discovery | undefined;
  try {
    discovery = discover(loadNginxConfig(saved.config.nginx.config));
  } catch (err) {
    out.warn(`can't read the nginx config to compare names: ${(err as Error).message}`);
  }
  const models = discovery ? buildModel({ config: saved.config, discovery, snippets: existingSnippets() }) : [];
  for (const name of imported) {
    const have = certbot.get(name)?.cert?.names ?? [];
    const model = models.find((m) => m.cert === name);
    out.info(`${out.bold(name)}: imported; ${snippetPath(name)} points at certbot's files.`);
    out.info(`  the certificate has: ${have.join(', ') || '(unreadable)'}`);
    if (!model || !model.included) {
      out.info(`  nginx doesn't use it yet: add include ${snippetPath(name)}; to its server blocks.`);
      out.info(`  For a certificate nginx doesn't use (e.g. for a mail server), give it its names in the config instead: zetcert update ${name} --add <name>`);
      continue;
    }
    const wanted = model.names.map((n) => n.name);
    const add = wanted.filter((n) => !have.includes(n));
    const remove = have.filter((n) => !wanted.includes(n));
    if (add.length === 0 && remove.length === 0) out.info('  nginx uses the same names.');
    else out.info(`  the next sync changes it: ${[...add.map((n) => `+ ${n}`), ...remove.map((n) => `- ${n}`)].join('  ')}`);
  }
  if (imported.length > 0) out.info('Nothing is issued until the next sync: sudo zetcert status, then sudo zetcert sync.');
  for (const p of problems) out.error(p);
  if (problems.length === 0) return 0;
  return imported.length > 0 ? 2 : 1;
}
