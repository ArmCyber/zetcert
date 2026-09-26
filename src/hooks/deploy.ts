// `zetcert hook deploy`, run by certbot's deploy hook directory after it renews a certificate:
// nginx -t, reload nginx, then the certificate's own deploy commands.
import path from 'node:path';
import { readCertbotCert } from '../certbot/reader';
import { certConfig, type Config, defaultConfig, loadConfig } from '../config/config';
import { loadState, saveState } from '../system/state';
import { sendAlert } from './notify';
import { nginxReload, nginxTest, runDeploy } from '../cli/nginx';
import type { Context } from '../cli/program';

export interface DeployFailure {
  event: 'reload-failed' | 'deploy-failed';
  message: string;
}

export async function deployHook(ctx: Context, env: NodeJS.ProcessEnv = process.env): Promise<number> {
  // sync reloads nginx once at the end and runs the deploy commands itself.
  if (env.ZETCERT_SYNC === '1') return 0;
  const lineage = env.RENEWED_LINEAGE ?? '';
  const cert = lineage ? path.basename(lineage) : '';
  const failures: DeployFailure[] = [];
  let config: Config;
  let configBroken = false;
  try {
    config = loadConfig(ctx.configPath).config;
  } catch (err) {
    // Still reload nginx, with the default commands: a typo in the config mustn't leave the old
    // certificate in place.
    ctx.out.error(`${(err as Error).message}\nzetcert uses the default nginx commands, and can't run ${cert || 'the certificate'}'s deploy commands or send alerts`);
    config = defaultConfig();
    configBroken = true;
  }

  const test = await nginxTest(config);
  if (!test.ok) {
    failures.push({ event: 'reload-failed', message: `nginx -t failed, so nginx still serves the old certificate:\n${test.output}` });
  } else {
    const reload = await nginxReload(config);
    if (!reload.ok) failures.push({ event: 'reload-failed', message: `reloading nginx failed, so it still serves the old certificate: ${reload.output}` });
  }
  for (const command of cert ? certConfig(config, cert).deploy : []) {
    const r = await runDeploy(command);
    if (!r.ok) failures.push({ event: 'deploy-failed', message: `deploy command failed: ${command}: ${r.output || 'no output'}` });
  }

  for (const f of failures) ctx.out.error(`${cert || 'certificate'}: ${f.message}`);
  if (failures.length > 0 && !configBroken) {
    const state = loadState();
    const renewed = cert ? readCertbotCert(cert)?.cert : undefined;
    // One alert per event, with every failure in it: "one a day" would drop a second one.
    for (const event of [...new Set(failures.map((f) => f.event))]) {
      const detail = failures.filter((f) => f.event === event).map((f) => f.message).join('\n');
      const sent = await sendAlert(config, { event, cert, expires: renewed?.notAfter, names: renewed?.names, detail }, state);
      if (sent.status === 'failed') ctx.out.error(`${cert}: the ${event} alert failed: ${sent.error}`);
    }
    saveState(state);
  }
  if (failures.length === 0 && !configBroken) ctx.out.info(`zetcert: reloaded nginx after renewing ${cert || 'a certificate'}.`);
  return failures.length > 0 || configBroken ? 1 : 0;
}
