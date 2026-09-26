// Runs certbot for zetcert: with ZETCERT_SYNC=1, so the directory hooks leave the reload to
// `sync`, and waiting while another certbot (e.g. its renewal timer) holds certbot's lock.
import { exec } from '../system/exec';
import { isBusy, isNotDue, parseRejected, type RejectedName } from './errors';

export interface CertbotResult {
  ok: boolean;
  code: number | null;
  output: string;
  rejected: RejectedName[];
  /** certbot kept the certificate: "Certificate not yet due for renewal". */
  notDue: boolean;
  /** Still busy after waiting the whole time. */
  busy: boolean;
}

export interface RunOptions {
  /** Shows certbot's output while it runs (-v). */
  onOutput?: (chunk: string) => void;
  /** Called while waiting for another certbot, with the time waited so far. */
  onBusy?: (waitedMs: number) => void;
  busyTimeoutMs?: number;
  retryDelayMs?: number;
  /** Tests replace the wait. */
  sleep?: (ms: number) => Promise<void>;
}

/** certbot can hold its lock through a random start delay of up to 8 minutes, and DNS validation takes minutes. */
export const BUSY_TIMEOUT_MS = 30 * 60_000;

export async function runCertbot(args: string[], options: RunOptions = {}): Promise<CertbotResult> {
  const timeout = options.busyTimeoutMs ?? BUSY_TIMEOUT_MS;
  const delay = options.retryDelayMs ?? 15_000;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let waited = 0;
  for (;;) {
    const r = await exec('certbot', args, { env: { ZETCERT_SYNC: '1' }, onOutput: options.onOutput });
    const output = `${r.stdout}\n${r.stderr}`;
    const busy = r.code !== 0 && isBusy(output);
    if (busy && waited < timeout) {
      options.onBusy?.(waited);
      await sleep(delay);
      waited += delay;
      continue;
    }
    return {
      ok: r.code === 0,
      code: r.code,
      output,
      rejected: r.code === 0 ? [] : parseRejected(output),
      notDue: isNotDue(output),
      busy,
    };
  }
}
