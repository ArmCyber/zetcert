// A fake certbot for tests: writes lineages and renewal files from its flags like certbot does.
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { parseCert } from '../../src/certbot/reader';
import type { Exec, ExecResult } from '../../src/system/exec';
import { makeCert, writeCertbotCert } from './certs-helper';

export interface FakeSystem {
  calls: string[][];
  version: string;
  /** Names the CA rejects. */
  reject: Set<string>;
  nginxTestFails: 'never' | 'always' | 'after-first';
  /** Shell commands run (nginx.test, nginx.reload, deploy commands). */
  shell: string[];
  exec: Exec;
}

const result = (code: number, stdout = '', stderr = ''): ExecResult => ({ code, stdout, stderr, timedOut: false });

function flag(args: readonly string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function renewalParams(args: readonly string[], names: string[]): string {
  const lines = ['account = testaccount', 'server = https://acme-v02.api.letsencrypt.org/directory', `key_type = ${flag(args, '--key-type') ?? 'ecdsa'}`];
  if (args.includes('--webroot')) {
    const w = flag(args, '-w') ?? '';
    lines.push('authenticator = webroot', `webroot_path = ${w},`, '[[webroot_map]]', ...names.map((n) => `${n} = ${w}`));
  } else if (args.includes('--manual')) {
    lines.push(
      'authenticator = manual',
      'pref_challs = dns-01,',
      `manual_auth_hook = ${flag(args, '--manual-auth-hook')}`,
      `manual_cleanup_hook = ${flag(args, '--manual-cleanup-hook')}`,
    );
  }
  return lines.join('\n');
}

/** certbot's output for failed challenges; a wildcard's identifier is its base name. */
function rejectedOutput(names: string[]): string {
  const identifiers = [...new Set(names.map((n) => n.replace(/^\*\./, '')))];
  return `Certbot failed to authenticate some domains (authenticator: webroot). The Certificate Authority reported these problems:\n${identifiers
    .map((n) => `  Domain: ${n}\n  Type:   dns\n  Detail: DNS problem: NXDOMAIN looking up A for ${n}\n`)
    .join('\n')}\nSome challenges have failed.`;
}

export function fakeSystem(root: { path: (p: string) => string; write: (p: string, c: string) => void }): FakeSystem {
  const sys: FakeSystem = {
    calls: [],
    version: '4.0.0',
    reject: new Set(),
    nginxTestFails: 'never',
    shell: [],
    exec: async (command, args) => {
      sys.calls.push([command, ...args]);
      if (command === 'sh') {
        const line = args[1] ?? '';
        sys.shell.push(line);
        if (line === 'nginx -t') {
          const tests = sys.shell.filter((l) => l === 'nginx -t').length;
          if (sys.nginxTestFails === 'always' || (sys.nginxTestFails === 'after-first' && tests > 1)) {
            return result(1, '', 'nginx: [emerg] something is wrong');
          }
        }
        return result(0);
      }
      if (command !== 'certbot') return result(0);
      const verb = args[0];
      if (verb === '--version') return result(0, `certbot ${sys.version}\n`);
      const cert = flag(args, '--cert-name') ?? '';
      const renewal = root.path(`/etc/letsencrypt/renewal/${cert}.conf`);
      if (verb === 'delete') {
        rmSync(root.path(`/etc/letsencrypt/live/${cert}`), { recursive: true, force: true });
        rmSync(renewal, { force: true });
        return result(0, `Deleted all files relating to certificate ${cert}.`);
      }
      if (verb === 'reconfigure') {
        const text = readFileSync(renewal, 'utf8');
        const names = [...text.matchAll(/^(\S+) = \S+$/gm)].map((m) => m[1] as string).filter((n) => n.includes('.') && !n.includes('_'));
        // Its test renewal validates every name of the certificate.
        const live = parseCert(readFileSync(root.path(`/etc/letsencrypt/live/${cert}/cert.pem`), 'utf8')).names;
        const failing = live.filter((n) => sys.reject.has(n));
        if (failing.length > 0) return result(1, '', rejectedOutput(failing));
        const head = text.slice(0, text.indexOf('[renewalparams]'));
        root.write(`/etc/letsencrypt/renewal/${cert}.conf`, `${head}[renewalparams]\n${renewalParams(args, names)}\n`);
        return result(0, 'Successfully updated configuration.');
      }
      // certonly
      const names = args.flatMap((a, i) => (a === '-d' ? [args[i + 1] as string] : []));
      const rejected = names.filter((n) => sys.reject.has(n));
      if (rejected.length > 0) return result(1, '', rejectedOutput(rejected));
      if (args.includes('--dry-run')) return result(0, 'The dry run was successful.');
      const live = root.path(`/etc/letsencrypt/live/${cert}/cert.pem`);
      if (existsSync(renewal) && existsSync(live) && !args.includes('--force-renewal')) {
        const current = parseCert(readFileSync(live, 'utf8'));
        const sameNames = current.names.length === names.length && names.every((n) => current.names.includes(n));
        if (sameNames && current.keyType === (flag(args, '--key-type') ?? 'ecdsa')) {
          return result(0, 'Certificate not yet due for renewal; no action taken.');
        }
      }
      writeCertbotCert(root.write, cert, makeCert({ names, keyType: flag(args, '--key-type') === 'rsa' ? 'rsa' : 'ecdsa', issuer: 'E7' }), renewalParams(args, names));
      return result(0, 'Successfully received certificate.');
    },
  };
  return sys;
}
