// Certificate and DNS account names become file names, so nothing else is accepted.
const NAME = /^[a-z0-9][a-z0-9.-]*$/;

export const NAME_RULE =
  'use only a-z, 0-9, dots and hyphens, start with a letter or digit, and at most 64 characters';

export function isValidName(name: string): boolean {
  return name.length <= 64 && NAME.test(name);
}

/** For `wildcard.<domain>` certificates, the domain; otherwise undefined. */
export function wildcardDomain(cert: string): string | undefined {
  return cert.startsWith('wildcard.') ? cert.slice('wildcard.'.length) : undefined;
}
