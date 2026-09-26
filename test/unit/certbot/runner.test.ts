import { afterEach, describe, expect, it } from 'vitest';
import { certonlyArgs, deleteArgs, type IssueSettings, reconfigureArgs } from '../../../src/certbot/commands';
import { failureSummary, isBusy, isNotDue, parseRejected } from '../../../src/certbot/errors';
import { runCertbot } from '../../../src/certbot/runner';
import { type ExecOptions, resetExec, setExec } from '../../../src/system/exec';

const http: IssueSettings = {
  cert: 'store',
  names: ['store.example', 'www.store.example'],
  keyType: 'ecdsa',
  validation: 'http',
  webroot: '/var/www/html',
  email: 'ops@example.com',
};
const dns: IssueSettings = { ...http, cert: 'wildcard.client.example', names: ['client.example', '*.client.example'], validation: 'dns', email: undefined };

describe('certbot command lines', () => {
  it('passes the full flag set to certonly', () => {
    expect(certonlyArgs(http)).toEqual([
      'certonly', '--non-interactive', '--agree-tos', '--cert-name', 'store',
      '-d', 'store.example', '-d', 'www.store.example', '--key-type', 'ecdsa',
      '--webroot', '-w', '/var/www/html', '--email', 'ops@example.com',
    ]);
  });

  it('uses the manual hooks for DNS and registers without email when there is none', () => {
    expect(certonlyArgs(dns)).toEqual([
      'certonly', '--non-interactive', '--agree-tos', '--cert-name', 'wildcard.client.example',
      '-d', 'client.example', '-d', '*.client.example', '--key-type', 'ecdsa',
      '--manual', '--preferred-challenges', 'dns',
      '--manual-auth-hook', '/usr/local/sbin/zetcert hook auth --cert wildcard.client.example',
      '--manual-cleanup-hook', '/usr/local/sbin/zetcert hook cleanup --cert wildcard.client.example',
      '--register-unsafely-without-email',
    ]);
  });

  it('adds --force-renewal and --dry-run when asked', () => {
    expect(certonlyArgs(http, { forceRenewal: true, dryRun: true }).slice(-2)).toEqual(['--force-renewal', '--dry-run']);
  });

  it('gives reconfigure the certonly flags without -d', () => {
    const args = reconfigureArgs(http);
    expect(args).toEqual([
      'reconfigure', '--non-interactive', '--agree-tos', '--cert-name', 'store', '--key-type', 'ecdsa',
      '--webroot', '-w', '/var/www/html', '--email', 'ops@example.com',
    ]);
    expect(args).not.toContain('-d');
  });

  it('deletes by name', () => {
    expect(deleteArgs('store')).toEqual(['delete', '--non-interactive', '--cert-name', 'store']);
  });
});

// Output captured from certbot 4.0.0 against Pebble.
const REJECTED = `Saving debug log to /var/log/letsencrypt/letsencrypt.log
Requesting a certificate for a.lab.test and broken.lab.test
Certbot failed to authenticate some domains (authenticator: webroot). The Certificate Authority reported these problems:
  Domain: broken.lab.test
  Type:   connection
  Detail: Get "http://broken.lab.test:80/.well-known/acme-challenge/YDHe4U": dial tcp 10.231.53.99:80: connect: no route to host

  Domain: other.lab.test
  Type:   dns
  Detail: DNS problem: NXDOMAIN looking up A for other.lab.test - check that a DNS record exists for this domain

Hint: The Certificate Authority failed to download the temporary challenge files created by Certbot.
Some challenges have failed.
Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile /var/log/letsencrypt/letsencrypt.log or re-run Certbot with -v for more details.`;

describe('reading certbot output', () => {
  it('finds the names the CA rejected, with the reason', () => {
    expect(parseRejected(REJECTED)).toEqual([
      {
        name: 'broken.lab.test',
        reason: 'connection: Get "http://broken.lab.test:80/.well-known/acme-challenge/YDHe4U": dial tcp 10.231.53.99:80: connect: no route to host',
      },
      { name: 'other.lab.test', reason: 'dns: DNS problem: NXDOMAIN looking up A for other.lab.test - check that a DNS record exists for this domain' },
    ]);
    expect(
      parseRejected('An unexpected error occurred:\nError creating new order :: Cannot issue for "bad_name.example.com": Domain name contains an invalid character'),
    ).toEqual([{ name: 'bad_name.example.com', reason: 'Domain name contains an invalid character' }]);
  });

  it('reads certbot 5, which says Identifier where 4.0 said Domain', () => {
    // Output captured from the certbot snap in CI, against Pebble.
    const output = `Renewing an existing certificate for shop.test and 2 more
Certbot failed to authenticate some domains (authenticator: webroot). The Certificate Authority reported these problems:
  Identifier: broken.shop.test
  Type:   connection
  Detail: Get "http://broken.shop.test:80/.well-known/acme-challenge/Es43cpSZ1m5w": dial tcp 10.231.53.99:80: connect: no route to host
Some challenges have failed.`;
    expect(parseRejected(output)).toEqual([
      {
        name: 'broken.shop.test',
        reason: 'connection: Get "http://broken.shop.test:80/.well-known/acme-challenge/Es43cpSZ1m5w": dial tcp 10.231.53.99:80: connect: no route to host',
      },
    ]);
  });

  it('recognizes "not yet due" and "already running"', () => {
    expect(isNotDue('Certificate not yet due for renewal; no action taken.')).toBe(true);
    expect(isBusy('Another instance of Certbot is already running.')).toBe(true);
    expect(isBusy(REJECTED)).toBe(false);
  });

  it('summarizes a failure without the boilerplate', () => {
    expect(failureSummary(REJECTED)).not.toContain('Saving debug log');
    expect(failureSummary(REJECTED)).toContain('Some challenges have failed.');
  });
});

describe('runCertbot', () => {
  afterEach(resetExec);

  it('runs certbot with ZETCERT_SYNC=1 and reports rejected names', async () => {
    let seen: ExecOptions | undefined;
    setExec(async (_c, _a, options) => {
      seen = options;
      return { code: 1, stdout: '', stderr: REJECTED, timedOut: false };
    });
    const r = await runCertbot(certonlyArgs(http));
    expect(seen?.env).toEqual({ ZETCERT_SYNC: '1' });
    expect(r).toMatchObject({ ok: false, code: 1, notDue: false, busy: false });
    expect(r.rejected.map((n) => n.name)).toEqual(['broken.lab.test', 'other.lab.test']);
  });

  it('waits while another certbot runs, then goes on', async () => {
    let runs = 0;
    setExec(async () => {
      runs++;
      return runs < 3
        ? { code: 1, stdout: '', stderr: 'Another instance of Certbot is already running.', timedOut: false }
        : { code: 0, stdout: 'Successfully received certificate.', stderr: '', timedOut: false };
    });
    const waits: number[] = [];
    const r = await runCertbot(['certonly'], { onBusy: (ms) => waits.push(ms), sleep: async () => {} });
    expect(r.ok).toBe(true);
    expect(waits).toEqual([0, 15_000]);
  });

  it('gives up after 30 minutes of waiting', async () => {
    setExec(async () => ({ code: 1, stdout: '', stderr: 'Another instance of Certbot is already running.', timedOut: false }));
    let slept = 0;
    const r = await runCertbot(['certonly'], { sleep: async (ms) => void (slept += ms) });
    expect(r).toMatchObject({ ok: false, busy: true });
    expect(slept).toBe(30 * 60_000);
  });
});
