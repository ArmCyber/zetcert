import { type ChildProcess, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Io } from '../../src/cli/program';
import type { Prompter } from '../../src/cli/prompt';
import { resetRoot, setRoot } from '../../src/system/paths';

/** Collects what a command prints. */
export function capture(
  answers: { confirm?: boolean; ask?: Record<string, string>; secret?: Record<string, string>; stdin?: string; interactive?: boolean } = {},
) {
  let stdout = '';
  let stderr = '';
  const questions: string[] = [];
  const prompter: Prompter = {
    interactive: answers.interactive ?? true,
    async confirm(question) {
      questions.push(question);
      return answers.confirm ?? true;
    },
    async ask(question, defaultValue) {
      questions.push(question);
      return answers.ask?.[question] ?? defaultValue;
    },
    async secret(question) {
      questions.push(question);
      return answers.secret?.[question] ?? '';
    },
  };
  const io: Io = {
    stdout: { write: (t: string) => (stdout += t) },
    stderr: { write: (t: string) => (stderr += t) },
    prompter,
    stdin: answers.stdin,
  };
  return { io, questions, stdout: () => stdout, stderr: () => stderr };
}

/** A temporary directory used as `/` for every path; `write` creates files in it. */
export function tempRoot() {
  const dir = mkdtempSync(path.join(tmpdir(), 'zetcert-test-'));
  setRoot(dir);
  return {
    dir,
    path: (p: string) => path.join(dir, p),
    write(p: string, content: string) {
      const file = path.join(dir, p);
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, content);
    },
    cleanup() {
      resetRoot();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** A process whose command line contains "zetcert", like a running sync, once it really runs. */
export async function zetcertLikeProcess(): Promise<ChildProcess> {
  const child = spawn('sh', ['-c', 'sleep 30; true', 'zetcert-test'], { stdio: 'ignore' });
  for (let i = 0; i < 200; i++) {
    try {
      if (readFileSync(`/proc/${child.pid}/cmdline`, 'utf8').includes('zetcert')) return child;
    } catch {
      // not there yet
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('the test process did not start');
}
