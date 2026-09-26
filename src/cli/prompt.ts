// Questions to the user. With -y, or when stdin is not a terminal, nothing is asked: a question
// answers yes and a prompt takes its default.
import { createInterface } from 'node:readline/promises';
import { UserError } from '../system/errors';

export interface Prompter {
  /** Whether questions reach a person: false with -y or when stdin is not a terminal. */
  readonly interactive: boolean;
  /** Yes/no; `defaultNo` for destructive actions, where Enter alone means no. */
  confirm(question: string, defaultNo?: boolean): Promise<boolean>;
  ask(question: string, defaultValue: string): Promise<string>;
  /** Hidden input, for credentials. Fails when there is no terminal to ask. */
  secret(question: string): Promise<string>;
}

/** Reads a line from the terminal without showing it. */
function readHidden(text: string): Promise<string> {
  const stdin = process.stdin;
  process.stderr.write(`${text} `);
  return new Promise((resolve, reject) => {
    let value = '';
    const done = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off('data', onData);
      process.stderr.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') return done(new UserError('cancelled'));
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.on('data', onData);
    stdin.resume();
  });
}

export function terminalPrompter(assumeYes: boolean): Prompter {
  const interactive = !assumeYes && process.stdin.isTTY === true;
  const question = async (text: string): Promise<string> => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      return (await rl.question(text)).trim();
    } finally {
      rl.close();
    }
  };
  return {
    interactive,
    async confirm(text, defaultNo = false) {
      if (!interactive) return true;
      const answer = (await question(`${text} ${defaultNo ? '[y/N]' : '[Y/n]'} `)).toLowerCase();
      if (answer === '') return !defaultNo;
      return answer === 'y' || answer === 'yes';
    },
    async ask(text, defaultValue) {
      if (!interactive) return defaultValue;
      const answer = await question(defaultValue ? `${text} [${defaultValue}] ` : `${text} `);
      return answer === '' ? defaultValue : answer;
    },
    async secret(text) {
      if (!interactive) throw new UserError('no terminal to ask for credentials: pass them on stdin with --from-stdin');
      return (await readHidden(text)).trim();
    },
  };
}
