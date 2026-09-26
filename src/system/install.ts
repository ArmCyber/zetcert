// The system copy: certbot runs zetcert's hooks as root from a timer with a minimal PATH, so
// zetcert lives in a fixed, root-owned place with a launcher, whatever installed Node and npm.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { copyFileAtomic, ensureDir, exists, readText, writeFileAtomic } from './fs';
import { LAUNCHER, LETSENCRYPT_DIR, onDisk, SYSTEM_DIR } from './paths';

export const SYSTEM_BUNDLE = `${SYSTEM_DIR}/zetcert.cjs`;
export const SYSTEM_NODE = `${SYSTEM_DIR}/node`;
export const INSTALL_JSON = `${SYSTEM_DIR}/install.json`;
export const DEPLOY_HOOK = `${LETSENCRYPT_DIR}/renewal-hooks/deploy/zetcert`;
export const POST_HOOK = `${LETSENCRYPT_DIR}/renewal-hooks/post/zetcert`;
export const LAUNCHER_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin';

export interface InstallInfo {
  version: string;
  /** The bundle of the npm install, where upgrades come from. */
  npm: string;
}

export function readInstallInfo(): InstallInfo | undefined {
  try {
    const raw = JSON.parse(readText(INSTALL_JSON) ?? '') as Partial<InstallInfo>;
    return typeof raw.version === 'string' && typeof raw.npm === 'string' ? { version: raw.version, npm: raw.npm } : undefined;
  } catch {
    return undefined;
  }
}

/** The version of an npm install, from the package.json above its dist/ directory. */
export function npmVersion(npmBundle: string): string | undefined {
  try {
    const pkg = JSON.parse(readText(path.join(path.dirname(path.dirname(npmBundle)), 'package.json')) ?? '') as {
      name?: string;
      version?: string;
    };
    return pkg.name === 'zetcert' && typeof pkg.version === 'string' ? pkg.version : undefined;
  } catch {
    return undefined;
  }
}

/** Compares versions like 1.2.3 and 1.2.3-rc.1: negative, zero or positive. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [main = '', pre] = v.split('-', 2);
    return { nums: main.split('.').map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === undefined) return 1;
  if (y.pre === undefined) return -1;
  return x.pre < y.pre ? -1 : 1;
}

let rootUidForTests = 0;

/** Tests only: the uid that counts as root for ownership checks. */
export function setRootUid(uid: number): void {
  rootUidForTests = uid;
}

/**
 * The first path, from `p` up to `/`, that isn't owned by root or is writable by others than root;
 * undefined when the whole chain is root-only. Symlinks are followed first.
 */
export function notRootOnly(p: string, rootUid = rootUidForTests): string | undefined {
  let current: string;
  try {
    current = realLogical(p);
  } catch {
    return p;
  }
  for (;;) {
    let st;
    try {
      st = statSync(onDisk(current));
    } catch {
      return current;
    }
    if (st.uid !== rootUid || (st.mode & 0o022) !== 0) return current;
    if (current === '/') return undefined;
    current = path.dirname(current);
  }
}

/** Resolves every symlink in `p`, keeping absolute targets inside the root used by tests. */
export function realLogical(p: string): string {
  const parts = path.resolve(p).split('/').filter(Boolean);
  let resolved = '/';
  for (let i = 0, hops = 0; i < parts.length; i++) {
    const next = path.join(resolved, parts[i] as string);
    const st = lstatSync(onDisk(next));
    if (st.isSymbolicLink()) {
      if (++hops > 40) throw new Error(`too many symbolic links: ${p}`);
      const target = readlinkSync(onDisk(next));
      const rest = parts.slice(i + 1);
      const joined = path.isAbsolute(target) ? target : path.join(resolved, target);
      parts.splice(0, parts.length, ...joined.split('/').filter(Boolean), ...rest);
      resolved = '/';
      i = -1;
      continue;
    }
    resolved = next;
  }
  return resolved;
}

export function launcherScript(): string {
  return `#!/bin/sh
# zetcert launcher, installed by zetcert init — do not edit.
# Runs the system copy with a fixed PATH, whatever PATH sudo or a systemd timer passes.
PATH=${LAUNCHER_PATH}
export PATH
for var in $(env | sed -n 's/^\\(LD_[A-Za-z0-9_]*\\)=.*/\\1/p'); do unset "$var"; done
exec ${SYSTEM_NODE} ${SYSTEM_BUNDLE} "$@"
`;
}

export function hookScript(kind: 'deploy' | 'post'): string {
  const when = kind === 'deploy' ? 'after it renews a certificate' : 'after each renewal run';
  return `#!/bin/sh
# Installed by zetcert init — do not edit. certbot runs this ${when}.
exec ${LAUNCHER} hook ${kind}
`;
}

function sameContent(a: string, b: string): boolean {
  try {
    const sa = statSync(onDisk(a));
    const sb = statSync(onDisk(b));
    if (sa.size !== sb.size) return false;
    const hash = (f: string) => createHash('sha256').update(readFileSync(onDisk(f))).digest('hex');
    return hash(a) === hash(b);
  } catch {
    return false;
  }
}

export interface InstallResult {
  /** The version installed before, when it was different. */
  upgradedFrom?: string;
  /** Node is a symlink to a root-owned binary; otherwise a copy of it. */
  nodeLinked: boolean;
  nodeFromSnap: boolean;
  firstInstall: boolean;
}

/**
 * Installs or refreshes the system copy from the running bundle and Node binary (real paths).
 * `rootUid` is for tests, where files belong to the test user.
 */
export function installSystemCopy(options: { bundle: string; node: string; version: string; rootUid?: number }): InstallResult {
  const previous = readInstallInfo();
  ensureDir(SYSTEM_DIR, 0o755);

  if (options.bundle !== SYSTEM_BUNDLE && !sameContent(options.bundle, SYSTEM_BUNDLE)) {
    copyFileAtomic(options.bundle, SYSTEM_BUNDLE, 0o755);
  }

  // Node: a symlink when root owns the binary and every directory above it, else a copy. A snap's
  // path changes with each refresh, so Node from a snap is copied too.
  const fromSnap = options.node.startsWith('/snap/');
  const linkable = !fromSnap && notRootOnly(options.node, options.rootUid ?? 0) === undefined;
  if (options.node !== SYSTEM_NODE) {
    let current: { link?: string; file: boolean } = { file: false };
    try {
      const st = lstatSync(onDisk(SYSTEM_NODE));
      current = st.isSymbolicLink() ? { link: readlinkSync(onDisk(SYSTEM_NODE)), file: false } : { file: st.isFile() };
    } catch {
      // not there yet
    }
    if (linkable && current.link !== options.node) {
      rmSync(onDisk(SYSTEM_NODE), { force: true });
      symlinkSync(options.node, onDisk(SYSTEM_NODE));
    } else if (!linkable && !(current.file && sameContent(options.node, SYSTEM_NODE))) {
      rmSync(onDisk(SYSTEM_NODE), { force: true });
      copyFileAtomic(options.node, SYSTEM_NODE, 0o755);
    }
  }

  // Where upgrades come from: the npm install that ran init, or the one recorded before.
  const npm = options.bundle === SYSTEM_BUNDLE ? (previous?.npm ?? '') : options.bundle;
  const info: InstallInfo = { version: options.version, npm };
  writeFileAtomic(INSTALL_JSON, `${JSON.stringify(info, null, 2)}\n`, 0o644);
  writeFileAtomic(LAUNCHER, launcherScript(), 0o755);

  return {
    upgradedFrom: previous && previous.version !== options.version ? previous.version : undefined,
    nodeLinked: linkable,
    nodeFromSnap: fromSnap,
    firstInstall: previous === undefined,
  };
}

/** A newer npm install to upgrade to, when running from the system copy. */
export function pendingUpgrade(runningBundle: string, runningVersion: string): { npm: string; version: string } | undefined {
  if (runningBundle !== SYSTEM_BUNDLE) return undefined;
  const info = readInstallInfo();
  if (!info?.npm || !exists(info.npm)) return undefined;
  const version = npmVersion(info.npm);
  if (!version || compareVersions(version, runningVersion) <= 0) return undefined;
  return { npm: info.npm, version };
}

export function copyNewBundle(npmBundle: string): void {
  copyFileAtomic(npmBundle, SYSTEM_BUNDLE, 0o755);
}

/** The npm copy's version when it is newer than the system copy (`status` and `doctor` warn). */
export function newerNpmCopy(): { npm: string; system: string } | undefined {
  const info = readInstallInfo();
  if (!info?.npm) return undefined;
  const version = npmVersion(info.npm);
  return version && compareVersions(version, info.version) > 0 ? { npm: version, system: info.version } : undefined;
}
