// Testing and reloading nginx with the commands from the config (nginx.test, nginx.reload).
import type { Config } from '../config/config';
import { shell } from '../system/exec';

export interface NginxResult {
  ok: boolean;
  output: string;
}

const TIMEOUT_MS = 120_000;

async function run(command: string): Promise<NginxResult> {
  try {
    const r = await shell(command, { timeoutMs: TIMEOUT_MS });
    const output = `${r.stdout}${r.stderr}`.trim();
    return { ok: r.code === 0 && !r.timedOut, output: r.timedOut ? `${command} took longer than ${TIMEOUT_MS / 1000}s` : output };
  } catch (err) {
    return { ok: false, output: (err as Error).message };
  }
}

export function nginxTest(config: Config): Promise<NginxResult> {
  return run(config.nginx.test);
}

export function nginxReload(config: Config): Promise<NginxResult> {
  return run(config.nginx.reload);
}

/** Runs a certificate's deploy command; each is stopped after 5 minutes. */
export async function runDeploy(command: string, timeoutMs = 5 * 60_000): Promise<NginxResult> {
  try {
    const r = await shell(command, { timeoutMs });
    if (r.timedOut) return { ok: false, output: `stopped after ${timeoutMs >= 60_000 ? `${timeoutMs / 60_000} minutes` : `${timeoutMs / 1000} s`}` };
    return { ok: r.code === 0, output: `${r.stdout}${r.stderr}`.trim() };
  } catch (err) {
    return { ok: false, output: (err as Error).message };
  }
}
