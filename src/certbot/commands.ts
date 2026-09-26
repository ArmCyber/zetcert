// certbot command lines. The full flag set goes with every issuance, because certbot rewrites
// a certificate's renewal settings from the flags of its last issuance.
import type { KeyType } from '../config/config';
import { LAUNCHER } from '../system/paths';

/** The manual hooks certbot saves for DNS-validated certificates. */
export function authHook(cert: string): string {
  return `${LAUNCHER} hook auth --cert ${cert}`;
}

export function cleanupHook(cert: string): string {
  return `${LAUNCHER} hook cleanup --cert ${cert}`;
}

export interface IssueSettings {
  cert: string;
  /** In the order certbot gets them; the first becomes the subject. */
  names: string[];
  keyType: KeyType;
  validation: 'http' | 'dns';
  webroot: string;
  email?: string;
}

function validationFlags(s: IssueSettings): string[] {
  if (s.validation === 'http') return ['--webroot', '-w', s.webroot];
  return [
    '--manual',
    '--preferred-challenges', 'dns',
    '--manual-auth-hook', authHook(s.cert),
    '--manual-cleanup-hook', cleanupHook(s.cert),
  ];
}

function accountFlags(s: IssueSettings): string[] {
  return s.email ? ['--email', s.email] : ['--register-unsafely-without-email'];
}

export function certonlyArgs(s: IssueSettings, options: { forceRenewal?: boolean; dryRun?: boolean } = {}): string[] {
  return [
    'certonly',
    '--non-interactive',
    '--agree-tos',
    '--cert-name', s.cert,
    ...s.names.flatMap((n) => ['-d', n]),
    '--key-type', s.keyType,
    ...validationFlags(s),
    ...accountFlags(s),
    ...(options.forceRenewal ? ['--force-renewal'] : []),
    ...(options.dryRun ? ['--dry-run'] : []),
  ];
}

/** `certbot reconfigure` (certbot ≥ 2.3): the certonly flags without -d, which it refuses. */
export function reconfigureArgs(s: IssueSettings): string[] {
  return [
    'reconfigure',
    '--non-interactive',
    '--agree-tos',
    '--cert-name', s.cert,
    '--key-type', s.keyType,
    ...validationFlags(s),
    ...accountFlags(s),
  ];
}

export function deleteArgs(cert: string): string[] {
  return ['delete', '--non-interactive', '--cert-name', cert];
}
