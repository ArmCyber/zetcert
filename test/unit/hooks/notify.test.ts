import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../../../src/cli/program';
import { defaultConfig } from '../../../src/config/config';
import { alertMessage, sendAlert } from '../../../src/hooks/notify';
import { type ExecOptions, resetExec, setExec } from '../../../src/system/exec';
import { setIsRoot } from '../../../src/system/root';
import { emptyState, loadState } from '../../../src/system/state';
import { makeCert, writeCertbotCert } from '../certs-helper';
import { capture, tempRoot } from '../helpers';

const DAY = 86_400_000;
const now = new Date('2026-10-30T12:00:00Z');

describe('alert message', () => {
  it('reads like the example in the spec', () => {
    const text = alertMessage(
      { event: 'renewal-failing', cert: 'store', expires: new Date('2026-11-20T12:00:00Z'), names: ['store.example', 'www.store.example', 'shop.store.example', 'x.store.example'] },
      'web1',
      now,
    );
    expect(text).toBe(`[web1] Certificate "store" is not renewing.
Expires 2026-11-20 (in 21 days). Names: store.example, www.store.example, …
Check: sudo zetcert status store · certbot log: /var/log/letsencrypt/letsencrypt.log
`);
  });

  it('covers the other events', () => {
    const expires = new Date('2026-11-02T12:00:00Z');
    expect(alertMessage({ event: 'expiring', cert: 'a', expires }, 'h', now)).toMatch(/^\[h\] Certificate "a" expires in 3 days\.\nExpires 2026-11-02 \(in 3 days\)\./);
    expect(alertMessage({ event: 'expiring', cert: 'a', expires: new Date('2026-10-28T12:00:00Z') }, 'h', now)).toContain('has expired.\nExpires 2026-10-28 (expired 2 days ago).');
    expect(alertMessage({ event: 'reload-failed', cert: 'a', detail: 'nginx: [emerg] bad' }, 'h', now)).toBe(
      `[h] nginx wasn't reloaded after certificate "a" was renewed, so it still serves the old one.\nnginx: [emerg] bad\nCheck: sudo zetcert status a · certbot log: /var/log/letsencrypt/letsencrypt.log\n`,
    );
    expect(alertMessage({ event: 'test', cert: '' }, 'h', now)).toBe('[h] Test alert from zetcert: notify works.\n');
  });
});

describe('sendAlert', () => {
  let calls: { command: string; options?: ExecOptions }[];
  let fail = false;
  beforeEach(() => {
    calls = [];
    fail = false;
    setExec(async (_c, args, options) => {
      calls.push({ command: args[1] as string, options });
      return fail ? { code: 7, stdout: '', stderr: 'curl: (7) failed', timedOut: false } : { code: 0, stdout: '', stderr: '', timedOut: false };
    });
  });
  afterEach(resetExec);
  const config = { ...defaultConfig(), notify: 'curl -s -K /etc/zetcert/ntfy.curl --data-binary @-' };
  const alert = { event: 'expiring' as const, cert: 'store', expires: new Date('2026-11-02T00:00:00Z'), names: ['store.example'] };

  it('runs the command with the message on stdin, the environment and a 60 s limit', async () => {
    expect(await sendAlert(config, alert, emptyState(), now)).toEqual({ status: 'sent' });
    expect(calls[0]?.command).toBe(config.notify);
    expect(calls[0]?.options?.input).toMatch(/Certificate "store" expires in 2 days/);
    expect(calls[0]?.options?.env).toMatchObject({ ZETCERT_EVENT: 'expiring', ZETCERT_CERT: 'store', ZETCERT_EXPIRES: '2026-11-02' });
    expect(calls[0]?.options?.env?.ZETCERT_HOST).toBeTruthy();
    expect(calls[0]?.options?.timeoutMs).toBe(60_000);
  });

  it('sends each certificate at most one alert per event per day', async () => {
    const state = emptyState();
    expect((await sendAlert(config, alert, state, now)).status).toBe('sent');
    expect((await sendAlert(config, alert, state, now)).status).toBe('already-sent');
    expect((await sendAlert(config, { ...alert, event: 'renewal-failing' }, state, now)).status).toBe('sent');
    expect((await sendAlert(config, alert, state, new Date(now.getTime() + DAY))).status).toBe('sent');
    expect(calls).toHaveLength(3);
  });

  it('reports failures and tries again next time', async () => {
    const state = emptyState();
    fail = true;
    expect(await sendAlert(config, alert, state, now)).toEqual({ status: 'failed', error: 'exit code 7: curl: (7) failed' });
    fail = false;
    expect((await sendAlert(config, alert, state, now)).status).toBe('sent');
  });

  it('sends nothing without a command', async () => {
    expect((await sendAlert(defaultConfig(), alert, emptyState(), now)).status).toBe('no-command');
    expect(calls).toEqual([]);
  });
});

describe('alerts from the hooks and notify --test', () => {
  let root: ReturnType<typeof tempRoot>;
  let shells: { command: string; options?: ExecOptions }[];
  beforeEach(() => {
    root = tempRoot();
    setIsRoot(true);
    shells = [];
    setExec(async (_c, args, options) => {
      shells.push({ command: args[1] as string, options });
      return args[1] === 'nginx -t' ? { code: 1, stdout: '', stderr: 'nginx: [emerg] broken', timedOut: false } : { code: 0, stdout: '', stderr: '', timedOut: false };
    });
    root.write('/etc/zetcert/config.yml', 'notify: cat > /dev/null\n');
    root.write('/etc/nginx/nginx.conf', 'http {\n  server { server_name ok.example; include /etc/nginx/zetcert/ok.conf; }\n  server { server_name failing.example; include /etc/nginx/zetcert/failing.conf; }\n  server { server_name expiring.example; include /etc/nginx/zetcert/expiring.conf; }\n}\n');
    const at = (daysAgo: number) => new Date(Date.now() - daysAgo * DAY);
    writeCertbotCert(root.write, 'ok', makeCert({ names: ['ok.example'], notBefore: at(10) }), '');
    writeCertbotCert(root.write, 'failing', makeCert({ names: ['failing.example'], notBefore: at(70) }), '');
    writeCertbotCert(root.write, 'expiring', makeCert({ names: ['expiring.example'], notBefore: at(85) }), '');
    writeCertbotCert(root.write, 'unmanaged', makeCert({ names: ['other.example'], notBefore: at(85) }), '');
  });
  afterEach(() => {
    root.cleanup();
    setIsRoot(undefined);
    resetExec();
    delete process.env.RENEWED_LINEAGE;
  });

  it('hook post alerts for managed certificates failing to renew or about to expire', async () => {
    const c = capture();
    expect(await run(['hook', 'post'], c.io)).toBe(0);
    const events = shells.map((s) => `${s.options?.env?.ZETCERT_EVENT} ${s.options?.env?.ZETCERT_CERT}`);
    expect(events.sort()).toEqual(['expiring expiring', 'renewal-failing failing']);
    expect(Object.keys(loadState().alerts).sort()).toEqual(['expiring', 'failing']);
    shells = [];
    await run(['hook', 'post'], capture().io);
    expect(shells).toEqual([]);
  });

  it('hook deploy sends reload-failed when nginx -t fails', async () => {
    process.env.RENEWED_LINEAGE = '/etc/letsencrypt/live/ok';
    const c = capture();
    expect(await run(['hook', 'deploy'], c.io)).toBe(1);
    const alert = shells.find((s) => s.command === 'cat > /dev/null');
    expect(alert?.options?.env?.ZETCERT_EVENT).toBe('reload-failed');
    expect(alert?.options?.input).toContain('nginx: [emerg] broken');
  });

  it('hook deploy sends one deploy-failed alert with every failed command', async () => {
    root.write('/etc/zetcert/config.yml', 'notify: cat > /dev/null\ncerts:\n  ok:\n    deploy: [a-fails, b-fails]\n');
    setExec(async (_c, args, options) => {
      shells.push({ command: args[1] as string, options });
      return args[1]?.endsWith('-fails') ? { code: 1, stdout: '', stderr: `${args[1]} broke`, timedOut: false } : { code: 0, stdout: '', stderr: '', timedOut: false };
    });
    process.env.RENEWED_LINEAGE = '/etc/letsencrypt/live/ok';
    expect(await run(['hook', 'deploy'], capture().io)).toBe(1);
    const alerts = shells.filter((s) => s.command === 'cat > /dev/null');
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.options?.input).toContain('deploy command failed: a-fails: a-fails broke\ndeploy command failed: b-fails: b-fails broke');
    expect(alerts[0]?.options?.input).not.toContain('Expires');
  });

  it('notify --test sends a test alert', async () => {
    const c = capture();
    expect(await run(['notify', '--test'], c.io)).toBe(0);
    expect(shells[0]?.options?.env?.ZETCERT_EVENT).toBe('test');
    expect(c.stdout()).toContain('Sent a test alert.');
    expect(await run(['notify'], capture().io)).toBe(1);
  });
});
