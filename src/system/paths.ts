// Every absolute path goes through here. The paths below are the ones nginx, certbot and the
// config see; onDisk() says where to read and write them, so tests can run in a temporary tree.
import path from 'node:path';

export const CONFIG_FILE = '/etc/zetcert/config.yml';
export const DNS_DIR = '/etc/zetcert/dns';
export const SNIPPET_DIR = '/etc/nginx/zetcert';
export const NGINX_CONFIG = '/etc/nginx/nginx.conf';
export const STATE_FILE = '/var/lib/zetcert/state.json';
export const PLACEHOLDER_DIR = '/var/lib/zetcert/placeholder';
export const LOCK_FILE = '/run/zetcert.lock';
export const SYSTEM_DIR = '/usr/local/lib/zetcert';
export const LAUNCHER = '/usr/local/sbin/zetcert';
export const LETSENCRYPT_DIR = '/etc/letsencrypt';

let root = '/';

/** Where the absolute path `p` is read and written. */
export function onDisk(p: string): string {
  if (!path.isAbsolute(p)) throw new Error(`not an absolute path: ${p}`);
  return root === '/' ? p : path.join(root, p);
}

/** Whether a test has put every path under a temporary directory. */
export function hasTestRoot(): boolean {
  return root !== '/';
}

/** Puts every path under `dir` instead of `/`. Tests only. */
export function setRoot(dir: string): void {
  root = path.resolve(dir);
}

export function resetRoot(): void {
  root = '/';
}
