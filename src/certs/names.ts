// DNS names as they go into certificates: lowercase ASCII (IDN as punycode), no trailing dot,
// optionally a leading `*.` wildcard label.
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
// eslint-disable-next-line no-control-regex -- ASCII check
const ASCII = /^[\x00-\x7f]*$/;

/**
 * The name lowercased, without a trailing dot and with IDN labels in punycode, or undefined when
 * the result isn't a valid DNS name. A leading `*.` is kept.
 */
export function normalizeDnsName(raw: string): string | undefined {
  let name = raw.toLowerCase();
  if (name.endsWith('.')) name = name.slice(0, -1);
  const wildcard = name.startsWith('*.');
  const base = wildcard ? name.slice(2) : name;
  if (base === '') return undefined;
  const ascii = ASCII.test(base) ? base : domainToASCII(base);
  if (!ascii) return undefined;
  const result = wildcard ? `*.${ascii}` : ascii;
  if (result.length > 253) return undefined;
  if (!ascii.split('.').every((label) => LABEL.test(label))) return undefined;
  return result;
}

/**
 * Like normalizeDnsName, but also requires what a certificate name needs: at least one dot and
 * not an IP address.
 */
export function normalizeCertName(raw: string): string | undefined {
  const name = normalizeDnsName(raw);
  // The dot and IP rules apply to the name without `*.`, so `*.com` isn't a name either.
  const base = name?.replace(/^\*\./, '');
  if (!name || !base?.includes('.') || isIP(base)) return undefined;
  return name;
}

export function isWildcard(name: string): boolean {
  return name.startsWith('*.');
}

/** The name without its first label: `a.b.example` → `b.example`, `*.b.example` → `b.example`. */
export function parentOf(name: string): string {
  return name.slice(name.indexOf('.') + 1);
}

/** Whether `name` is `domain` itself or any name below it. */
export function isWithin(name: string, domain: string): boolean {
  return name === domain || name.endsWith(`.${domain}`);
}

export type ServerNameResult =
  /** Usable: one name, or two for `.example.com`. */
  | { names: string[] }
  /** Skipped; `warn` names shown as warnings, the others only with `status -v`. */
  | { skip: string; warn: boolean };

/** How a `server_name` value is used. */
export function readServerName(raw: string): ServerNameResult {
  // Before the `$` check: regular expressions usually end with `$`.
  if (raw.startsWith('~')) return { skip: 'regular expression; add the names to the config if needed', warn: true };
  if (raw.includes('$')) return { skip: 'contains a variable', warn: false };
  if (raw === '') return { skip: 'empty name', warn: false };
  if (raw === '_') return { skip: 'catch-all name', warn: false };
  let name = raw.toLowerCase();
  if (name.endsWith('.')) name = name.slice(0, -1);
  if (name.endsWith('.*')) return { skip: 'wildcard at the end; add the names to the config if needed', warn: true };
  if (name === 'localhost') return { skip: 'localhost', warn: false };
  const bare = name.startsWith('[') && name.endsWith(']') ? name.slice(1, -1) : name;
  if (isIP(bare)) return { skip: 'IP address', warn: false };
  const dotted = name.startsWith('.') ? name.slice(1) : name;
  if (!(dotted.startsWith('*.') ? dotted.slice(2) : dotted).includes('.')) return { skip: 'no dot in the name', warn: false };
  const normalized = normalizeDnsName(dotted);
  if (!normalized || (name.startsWith('.') && isWildcard(normalized))) {
    return { skip: 'not a valid DNS name', warn: true };
  }
  return { names: name.startsWith('.') ? [normalized, `*.${normalized}`] : [normalized] };
}
