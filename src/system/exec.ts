// Every external command (certbot, nginx, systemctl, openssl, sudo, user commands) runs through here,
// so tests can replace them with setExec().
import { spawn } from 'node:child_process';

export interface ExecOptions {
  /** Added to this process's environment; `undefined` removes a variable. */
  env?: Record<string, string | undefined>;
  /** Written to the command's stdin, which is then closed. */
  input?: string;
  /** Stops the command, and everything it started, after this many milliseconds. */
  timeoutMs?: number;
  /** Receives the output while the command runs, e.g. to show certbot's output with -v. */
  onOutput?: (chunk: string) => void;
  /** Connects the command to this terminal instead of capturing its input and output. */
  interactive?: boolean;
}

export interface ExecResult {
  /** The exit code, or null when the command was stopped by a signal. */
  code: number | null;
  stdout: string;
  stderr: string;
  /** The command ran longer than `timeoutMs` and was stopped. */
  timedOut: boolean;
}

export type Exec = (command: string, args: readonly string[], options?: ExecOptions) => Promise<ExecResult>;

/** Runs a command. Rejects only when it can't be started, e.g. ENOENT when it isn't installed. */
export const spawnExec: Exec = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const env = { ...process.env };
    for (const [name, value] of Object.entries(options.env ?? {})) {
      if (value === undefined) delete env[name];
      else env[name] = value;
    }
    const bounded = options.timeoutMs !== undefined;
    const child = spawn(command, args, {
      env,
      stdio: options.interactive ? 'inherit' : 'pipe',
      // A process group of its own, so a timeout also stops what a shell command started.
      detached: bounded,
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    child.stdout?.setEncoding('utf8').on('data', (chunk: string) => {
      stdout += chunk;
      options.onOutput?.(chunk);
    });
    child.stderr?.setEncoding('utf8').on('data', (chunk: string) => {
      stderr += chunk;
      options.onOutput?.(chunk);
    });
    // The command may exit without reading its input.
    child.stdin?.on('error', () => {});
    child.stdin?.end(options.input ?? '');

    const timer = bounded
      ? setTimeout(() => {
          timedOut = true;
          if (child.pid !== undefined) {
            try {
              process.kill(-child.pid, 'SIGKILL');
            } catch {
              // already gone
            }
          }
          // Something that left the process group may still hold the pipes open.
          child.stdout?.destroy();
          child.stderr?.destroy();
        }, options.timeoutMs)
      : undefined;

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });

let current: Exec = spawnExec;

export function exec(command: string, args: readonly string[], options?: ExecOptions): Promise<ExecResult> {
  return current(command, args, options);
}

/** Runs a shell command line, such as `nginx.reload` from the config, with `sh -c`. */
export function shell(commandLine: string, options?: ExecOptions): Promise<ExecResult> {
  return current('sh', ['-c', commandLine], options);
}

/** Replaces how commands run. Tests only. */
export function setExec(fake: Exec): void {
  current = fake;
}

export function resetExec(): void {
  current = spawnExec;
}
