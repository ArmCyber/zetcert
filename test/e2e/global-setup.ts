// Builds the test bundle, packs it like npm publish would, starts the lab and installs zetcert with npm.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { COMPOSE, E2E_DIR, E2E_MOUNT, HOST, sh, spawnCollect } from './target';

const ROOT = path.resolve(E2E_DIR, '../..');
const BUILD = path.join(E2E_DIR, '.build');

function run(command: string, args: string[]) {
  execFileSync(command, args, { cwd: ROOT, stdio: 'inherit' });
}

export async function setup(): Promise<void> {
  rmSync(BUILD, { recursive: true, force: true });
  run('node', ['scripts/build.js', '--e2e']);
  const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  const { name, version, description, license, os, engines, bin, files } = pkg;
  mkdirSync(path.join(BUILD, 'package'), { recursive: true });
  writeFileSync(
    path.join(BUILD, 'package', 'package.json'),
    JSON.stringify({ name, version, description, license, os, engines, bin, files }, null, 2),
  );
  copyFileSync(path.join(ROOT, 'LICENSE'), path.join(BUILD, 'package', 'LICENSE'));
  run('npm', ['pack', '--silent', '--ignore-scripts', '--pack-destination', BUILD, path.join(BUILD, 'package')]);

  if (!HOST) {
    run('docker', [...COMPOSE, 'down', '-v', '--remove-orphans']);
    run('docker', [...COMPOSE, 'up', '-d', '--build', '--force-recreate', '--wait']);
  }
  // Wait for Pebble.
  for (let i = 0; ; i++) {
    const r = await sh('curl -sf --cacert "$REQUESTS_CA_BUNDLE" https://pebble:14000/dir >/dev/null');
    if (r.code === 0) break;
    if (i > 60) throw new Error(`Pebble didn't start: ${r.stderr}`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  const tgz = `${E2E_MOUNT}/.build/zetcert-${String(version)}.tgz`;
  // In the container npm's global prefix is root-owned (apt), like `sudo npm install -g`; the CI
  // runner's Node belongs to the CI user.
  const install = HOST
    ? await spawnCollect('npm', ['install', '-g', '--no-audit', '--no-fund', tgz])
    : await sh(`npm install -g --no-audit --no-fund ${tgz}`);
  if (install.code !== 0) throw new Error(`npm install failed:\n${install.stdout}\n${install.stderr}`);
}

export async function teardown(): Promise<void> {
  if (!HOST && !process.env.E2E_KEEP) run('docker', [...COMPOSE, 'down', '-v', '--remove-orphans']);
}
