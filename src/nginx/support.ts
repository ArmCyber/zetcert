// zetcert's support files in /etc/nginx/zetcert: _tls.conf, _ffdhe2048.pem and _acme.conf.
import type { Config, TlsKey, TlsOverrides } from '../config/config';
import { readText } from '../system/fs';
import { formatLoc } from '../system/loc';
import { SNIPPET_DIR } from '../system/paths';
import type { Discovery } from './discovery';

export const TLS_CONF = `${SNIPPET_DIR}/_tls.conf`;
export const DHPARAM_FILE = `${SNIPPET_DIR}/_ffdhe2048.pem`;
export const ACME_CONF = `${SNIPPET_DIR}/_acme.conf`;

/** The RFC 7919 ffdhe2048 group: the same parameters as certbot's ssl-dhparams.pem. */
export const FFDHE2048_PEM = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
`;

/** certbot's values (Mozilla's "intermediate" profile), with the cache zone named zetcert. */
export const TLS_DEFAULTS: Record<TlsKey, string> = {
  session_cache: 'shared:zetcert:10m',
  session_timeout: '1d',
  session_tickets: 'off',
  protocols: 'TLSv1.2 TLSv1.3',
  prefer_server_ciphers: 'off',
  ciphers:
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
  dhparam: 'ffdhe2048',
};

export function tlsConfContent(overrides: TlsOverrides): string {
  const v = { ...TLS_DEFAULTS, ...overrides };
  const fromConfig = (Object.keys(overrides) as TlsKey[]).filter((k) => overrides[k] !== undefined);
  const lines = ['# Managed by zetcert — do not edit. Change settings in /etc/zetcert/config.yml (tls).'];
  if (fromConfig.length > 0) lines.push(`# From the config: ${fromConfig.join(', ')}. The rest are zetcert's defaults.`);
  lines.push(
    `ssl_session_cache ${v.session_cache};`,
    `ssl_session_timeout ${v.session_timeout};`,
    `ssl_session_tickets ${v.session_tickets};`,
    '',
    `ssl_protocols ${v.protocols};`,
    `ssl_prefer_server_ciphers ${v.prefer_server_ciphers};`,
    '',
    `ssl_ciphers "${v.ciphers}";`,
  );
  if (v.dhparam !== 'off') lines.push(`ssl_dhparam ${v.dhparam === 'ffdhe2048' ? DHPARAM_FILE : v.dhparam};`);
  return `${lines.join('\n')}\n`;
}

export function acmeConfContent(webroot: string): string {
  return `# Managed by zetcert — do not edit. Change the webroot in /etc/zetcert/config.yml.
location ^~ /.well-known/acme-challenge/ {
    root ${webroot};
    default_type text/plain;
    try_files $uri =404;
}
`;
}

export type TlsFilePlan =
  | { action: 'write'; content: string }
  /** `tls: off`, but nginx still includes the file: deleting it would break `nginx -t`. */
  | { action: 'keep'; warning: string }
  | { action: 'remove' };

/**
 * What to do with _tls.conf (`tls: off`). `includes` are the support-file includes found in nginx,
 * or undefined when the nginx config couldn't be read.
 */
export function tlsFilePlan(tls: TlsOverrides | 'off', includes: Discovery['supportIncludes'] | undefined): TlsFilePlan {
  if (tls !== 'off') return { action: 'write', content: tlsConfContent(tls) };
  if (!includes) return { action: 'keep', warning: `tls: off, but the nginx config couldn't be read, so ${TLS_CONF} stays for now` };
  const include = includes.find((i) => i.path === TLS_CONF);
  if (include) {
    return {
      action: 'keep',
      warning: `tls: off, but ${formatLoc(include)} still includes ${TLS_CONF}, so it stays until that include is removed`,
    };
  }
  return { action: 'remove' };
}

export interface SupportFiles {
  tls: TlsFilePlan;
  /** Lines like "/etc/nginx/zetcert/_tls.conf to update", for the files that differ. */
  changes: string[];
}

/** Which of _tls.conf and _acme.conf differ from what zetcert writes (status and sync). */
export function supportFileChanges(config: Config, includes: Discovery['supportIncludes'] | undefined): SupportFiles {
  const tls = tlsFilePlan(config.tls, includes);
  const changes: string[] = [];
  const current = readText(TLS_CONF);
  if (tls.action === 'write' && current !== tls.content) changes.push(`${TLS_CONF} to ${current === undefined ? 'create' : 'update'}`);
  if (tls.action === 'remove' && current !== undefined) changes.push(`${TLS_CONF} to delete (tls: off)`);
  const acme = readText(ACME_CONF);
  if (acme !== acmeConfContent(config.webroot)) changes.push(`${ACME_CONF} to ${acme === undefined ? 'create' : 'update'}`);
  return { tls, changes };
}
