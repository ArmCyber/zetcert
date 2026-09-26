// `zetcert notify --test`: sends a test alert through the notify command.
import { loadConfig } from '../config/config';
import { sendAlert } from '../hooks/notify';
import { UserError } from '../system/errors';
import type { Context } from './program';

export async function notify(ctx: Context, options: { test?: boolean }): Promise<number> {
  if (!options.test) throw new UserError('zetcert notify --test sends a test alert; the certbot hooks send the others');
  const config = loadConfig(ctx.configPath).config;
  if (!config.notify) throw new UserError(`there's no notify command in ${ctx.configPath}`);
  const result = await sendAlert(config, { event: 'test', cert: '' }, undefined);
  if (result.status === 'failed') throw new UserError(`the notify command failed: ${result.error}`);
  ctx.out.info('Sent a test alert.');
  return 0;
}
