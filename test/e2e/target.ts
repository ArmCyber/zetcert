// Where the end-to-end tests run commands: in the Docker server container (default), or on this
// machine with sudo (E2E_TARGET=host, the CI job with the certbot snap).
import { spawn } from 'node:child_process';
import path from 'node:path';

export const HOST = process.env.E2E_TARGET === 'host';
export const E2E_DIR = __dirname;
export const COMPOSE = ['compose', '-f', path.join(E2E_DIR, 'compose.yml')];
/** The server's address, which challtestsrv gives every name. */
export const SERVER_IP = process.env.E2E_SERVER_IP ?? '10.231.53.4';
/** Where the test files are inside the target. */
export const E2E_MOUNT = HOST ? E2E_DIR : '/e2e';

export interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

export function spawnCollect(command: string, args: string[], input?: string): Promise<Result> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c: Buffer) => (stdout += c.toString()));
    child.stderr.on('data', (c: Buffer) => (stderr += c.toString()));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input ?? '');
  });
}

/** Runs a shell command as root on the server. */
export function sh(command: string): Promise<Result> {
  return HOST
    ? spawnCollect('sudo', ['-E', 'sh', '-c', command])
    : spawnCollect('docker', [...COMPOSE, 'exec', '-T', 'server', 'sh', '-c', command]);
}

/** Runs a shell command as a normal user: `tester` in the container, the CI user on the host. */
export function asUser(command: string): Promise<Result> {
  return HOST
    ? spawnCollect('sh', ['-c', command])
    : spawnCollect('docker', [...COMPOSE, 'exec', '-T', '-u', 'tester', 'server', 'sh', '-c', command]);
}

/** Like sh, but throws when the command fails. */
export async function ok(command: string): Promise<string> {
  const r = await sh(command);
  if (r.code !== 0) throw new Error(`${command} exited with ${r.code}:\n${r.stdout}\n${r.stderr}`);
  return r.stdout;
}

/** Writes a file on the server. */
export async function write(file: string, content: string): Promise<void> {
  const r = HOST
    ? await spawnCollect('sudo', ['sh', '-c', `mkdir -p "$(dirname '${file}')" && cat > '${file}'`], content)
    : await spawnCollect('docker', [...COMPOSE, 'exec', '-T', 'server', 'sh', '-c', `mkdir -p "$(dirname '${file}')" && cat > '${file}'`], content);
  if (r.code !== 0) throw new Error(`writing ${file} failed: ${r.stderr}`);
}

/** Tells challtestsrv to answer A queries for `name` with `ip`. */
export async function setA(name: string, ip: string): Promise<void> {
  await ok(`curl -sf -X POST -d '{"host":"${name}.","addresses":["${ip}"]}' http://${HOST ? '10.231.53.3' : 'challtestsrv'}:8055/add-a`);
}
