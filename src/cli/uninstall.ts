// `zetcert uninstall`: removes the system copy, the launcher and the certbot hooks. The config,
// the snippets and the certificates stay, and a plain deploy hook keeps nginx reloading after
// certbot renews.
import { rmSync } from 'node:fs';
import path from 'node:path';
import { readCertbotCerts } from '../certbot/reader';
import { loadConfig } from '../config/config';
import { UserError } from '../system/errors';
import { exists, writeFileAtomic } from '../system/fs';
import { DEPLOY_HOOK, POST_HOOK } from '../system/install';
import { LAUNCHER, onDisk, SYSTEM_DIR } from '../system/paths';
import type { Context } from './program';

export const PLAIN_DEPLOY_HOOK = `${path.dirname(DEPLOY_HOOK)}/nginx-reload`;
export const PLAIN_HOOK_MARKER = 'Left by zetcert uninstall';

export async function uninstall(ctx: Context, options: { force?: boolean }): Promise<number> {
  const { out } = ctx;
  const config = loadConfig(ctx.configPath).config;
  // Their renewal settings call zetcert's DNS hooks, so they can't renew without zetcert.
  const dnsCerts = readCertbotCerts().filter((c) => c.renewal.manualAuthHook?.includes(`${LAUNCHER} hook auth`));
  if (dnsCerts.length > 0 && !options.force) {
    throw new UserError(
      `these DNS-validated certificates renew through zetcert's hooks: ${dnsCerts.map((c) => c.name).join(', ')}. Delete or move them first, or use --force (their renewals will fail)`,
    );
  }
  // The plain hook takes over zetcert's reload: without zetcert's hook (init stopped early) there is
  // nothing to take over.
  const replaceHook = exists(DEPLOY_HOOK);
  const plain = `#!/bin/sh\n# ${PLAIN_HOOK_MARKER}: reloads nginx after certbot renews a certificate.\n${config.nginx.test} && ${config.nginx.reload}\n`;
  out.info('Uninstalling will:');
  out.info(`  - remove ${SYSTEM_DIR} and ${LAUNCHER}`);
  out.info(`  - remove the certbot hooks ${DEPLOY_HOOK} and ${POST_HOOK}`);
  if (replaceHook) out.info(`  - add ${PLAIN_DEPLOY_HOOK}: ${config.nginx.test} && ${config.nginx.reload}`);
  out.info(`It keeps ${ctx.configPath}, the snippets in /etc/nginx/zetcert and the certificates.`);
  const deploys = Object.entries(config.certs).filter(([, c]) => c.deploy.length > 0);
  if (deploys.length > 0) {
    out.warn(
      `these deploy commands stop running after renewals; add them to certbot (e.g. certbot reconfigure --cert-name <cert> --deploy-hook '<command>') if they are still needed:\n${deploys
        .map(([cert, c]) => `  ${cert}: ${c.deploy.join('; ')}`)
        .join('\n')}`,
    );
  }
  if (!(await ctx.prompt.confirm('Uninstall zetcert?', true))) {
    out.info('Nothing changed.');
    return 1;
  }
  if (replaceHook) writeFileAtomic(PLAIN_DEPLOY_HOOK, plain, 0o755);
  for (const hook of [DEPLOY_HOOK, POST_HOOK]) rmSync(onDisk(hook), { force: true });
  rmSync(onDisk(LAUNCHER), { force: true });
  rmSync(onDisk(SYSTEM_DIR), { recursive: true, force: true });
  out.info('zetcert is uninstalled. To remove the npm package too: npm uninstall -g zetcert');
  if (exists(ctx.configPath)) out.info(`Its settings stay in ${path.dirname(ctx.configPath)}.`);
  return 0;
}
