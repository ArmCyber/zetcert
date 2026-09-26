// Alerts through the `notify` command from the config: run as root with `sh -c`, the message
// on stdin and ZETCERT_EVENT, ZETCERT_CERT, ZETCERT_EXPIRES, ZETCERT_HOST in the environment,
// stopped after 60 s. At most one alert per certificate per event per day.
import { hostname } from 'node:os';
import { daysLeft, isoDay } from '../certs/health';
import type { Config } from '../config/config';
import { shell } from '../system/exec';
import type { State } from '../system/state';

export type NotifyEvent = 'renewal-failing' | 'expiring' | 'reload-failed' | 'deploy-failed' | 'test';

export interface Alert {
  event: NotifyEvent;
  /** Empty for the test alert. */
  cert: string;
  expires?: Date;
  names?: string[];
  /** More about the failure, e.g. nginx's error. */
  detail?: string;
}

export type SendResult = { status: 'sent' | 'no-command' | 'already-sent' } | { status: 'failed'; error: string };

function namesText(names: string[]): string {
  return names.length > 3 ? `${names.slice(0, 2).join(', ')}, …` : names.join(', ');
}

export function alertMessage(alert: Alert, host: string, now: Date): string {
  const { cert, expires } = alert;
  const left = expires ? daysLeft(expires, now) : 0;
  const first: Record<NotifyEvent, string> = {
    'renewal-failing': `Certificate "${cert}" is not renewing.`,
    expiring: left < 0 ? `Certificate "${cert}" has expired.` : `Certificate "${cert}" expires in ${left} day${left === 1 ? '' : 's'}.`,
    'reload-failed': `nginx wasn't reloaded after certificate "${cert}" was renewed, so it still serves the old one.`,
    'deploy-failed': `A deploy command of certificate "${cert}" failed after its renewal.`,
    test: 'Test alert from zetcert: notify works.',
  };
  const lines = [`[${host}] ${first[alert.event]}`];
  // The expiry matters for the expiry alerts; after a failed reload nginx still serves the old one.
  if (expires && (alert.event === 'renewal-failing' || alert.event === 'expiring')) {
    const when = left < 0 ? `expired ${-left} day${left === -1 ? '' : 's'} ago` : `in ${left} day${left === 1 ? '' : 's'}`;
    lines.push(`Expires ${isoDay(expires)} (${when}).${alert.names?.length ? ` Names: ${namesText(alert.names)}` : ''}`);
  }
  if (alert.detail) lines.push(alert.detail);
  if (alert.event !== 'test') {
    lines.push(`Check: sudo zetcert status ${cert} · certbot log: /var/log/letsencrypt/letsencrypt.log`);
  }
  return `${lines.join('\n')}\n`;
}

/** Sends an alert unless there's no notify command or it was sent today (the test alert always goes). */
export async function sendAlert(config: Config, alert: Alert, state: State | undefined, now = new Date()): Promise<SendResult> {
  if (!config.notify) return { status: 'no-command' };
  const day = isoDay(now);
  if (alert.event !== 'test' && state?.alerts[alert.cert]?.[alert.event] === day) return { status: 'already-sent' };
  const host = hostname();
  let error: string | undefined;
  try {
    const r = await shell(config.notify, {
      input: alertMessage(alert, host, now),
      env: {
        ZETCERT_EVENT: alert.event,
        ZETCERT_CERT: alert.cert,
        ZETCERT_EXPIRES: alert.expires ? isoDay(alert.expires) : '',
        ZETCERT_HOST: host,
      },
      timeoutMs: 60_000,
    });
    if (r.timedOut) error = 'stopped after 60 s';
    else if (r.code !== 0) error = `exit code ${r.code}: ${(r.stderr || r.stdout).trim()}`;
  } catch (err) {
    error = (err as Error).message;
  }
  if (error) return { status: 'failed', error };
  if (state && alert.event !== 'test') {
    state.alerts[alert.cert] ??= {};
    (state.alerts[alert.cert] as Record<string, string>)[alert.event] = day;
  }
  return { status: 'sent' };
}
