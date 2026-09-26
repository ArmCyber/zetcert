// `zetcert hook post`, run by certbot's post hook directory after each renewal run: alerts
// when a managed certificate is failing to renew or about to expire.
import type { Context } from '../cli/program';
import { readCertbotCerts } from '../certbot/reader';
import { daysLeft, EXPIRING_DAYS, renewalFailing } from '../certs/health';
import { buildModel } from '../certs/model';
import { loadConfig } from '../config/config';
import { discover } from '../nginx/discovery';
import { loadNginxConfig } from '../nginx/include';
import { existingSnippets } from '../nginx/snippets';
import { loadState, saveState } from '../system/state';
import { sendAlert } from './notify';

export async function postHook(ctx: Context, env: NodeJS.ProcessEnv = process.env, now = new Date()): Promise<number> {
  if (env.ZETCERT_SYNC === '1') return 0;
  let config;
  try {
    config = loadConfig(ctx.configPath).config;
  } catch (err) {
    ctx.out.error(`${(err as Error).message}\nzetcert can't check the certificates or send alerts until the config is fixed`);
    return 1;
  }
  let managed: Set<string>;
  try {
    const models = buildModel({ config, discovery: discover(loadNginxConfig(config.nginx.config)), snippets: existingSnippets() });
    managed = new Set(models.map((m) => m.cert));
  } catch {
    // Without the nginx config: the certificates with a snippet or a config entry.
    managed = new Set([...existingSnippets(), ...Object.keys(config.certs)]);
  }
  const state = loadState();
  let failed = false;
  for (const cert of readCertbotCerts()) {
    if (!managed.has(cert.name) || !cert.cert) continue;
    const { notBefore, notAfter, names } = cert.cert;
    const event =
      daysLeft(notAfter, now) < EXPIRING_DAYS ? 'expiring' : renewalFailing(notBefore, notAfter, now) ? 'renewal-failing' : undefined;
    if (!event) continue;
    const result = await sendAlert(config, { event, cert: cert.name, expires: notAfter, names }, state, now);
    if (result.status === 'failed') {
      ctx.out.error(`${cert.name}: the ${event} alert failed: ${result.error}`);
      failed = true;
    } else if (result.status === 'sent') {
      ctx.out.info(`zetcert: sent a ${event} alert for ${cert.name}`);
    } else if (result.status === 'no-command') {
      ctx.out.error(`${cert.name}: ${event === 'expiring' ? 'expires soon' : 'is not renewing'}, and there's no notify command in the config`);
    }
  }
  saveState(state);
  return failed ? 1 : 0;
}
