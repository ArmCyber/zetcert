// zetcert's own files in /etc/nginx/zetcert: `<cert>.conf` snippets and `_…` support files.
import type { FileBatch } from '../system/files';
import { listDir } from '../system/fs';
import { LETSENCRYPT_DIR, PLACEHOLDER_DIR, SNIPPET_DIR } from '../system/paths';

export function snippetPath(cert: string): string {
  return `${SNIPPET_DIR}/${cert}.conf`;
}

/** The certificates that have a snippet file; support files (`_…`) aren't certificates. */
export function existingSnippets(): string[] {
  return listDir(SNIPPET_DIR)
    .filter((f) => f.endsWith('.conf') && !f.startsWith('_'))
    .map((f) => f.slice(0, -'.conf'.length));
}

export const PLACEHOLDER_CERT = `${PLACEHOLDER_DIR}/fullchain.pem`;
export const PLACEHOLDER_KEY = `${PLACEHOLDER_DIR}/privkey.pem`;

/** The snippet: certbot's files when certbot has the certificate, otherwise the placeholder. */
export function snippetContent(cert: string, certbotHasIt: boolean): string {
  const [fullchain, privkey] = certbotHasIt
    ? [`${LETSENCRYPT_DIR}/live/${cert}/fullchain.pem`, `${LETSENCRYPT_DIR}/live/${cert}/privkey.pem`]
    : [PLACEHOLDER_CERT, PLACEHOLDER_KEY];
  return `# Managed by zetcert — do not edit. Certificate: ${cert}
ssl_certificate     ${fullchain};
ssl_certificate_key ${privkey};
`;
}

/** Whether a snippet's content points at the placeholder. */
export function usesPlaceholder(content: string | undefined): boolean {
  return content?.includes(PLACEHOLDER_CERT) ?? false;
}

/** Writes a certificate's snippet (0644, no secrets) if it changed. */
export function writeSnippet(batch: FileBatch, cert: string, certbotHasIt: boolean): boolean {
  return batch.write(snippetPath(cert), snippetContent(cert, certbotHasIt), 0o644);
}
