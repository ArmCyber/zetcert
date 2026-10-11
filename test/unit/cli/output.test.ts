import { describe, expect, it } from 'vitest';
import { Output } from '../../../src/cli/output';

function output(options: { quiet?: boolean; color?: boolean; isTTY?: boolean } = {}) {
  let stdout = '';
  let stderr = '';
  const out = new Output({
    stdout: { write: (text: string) => (stdout += text) },
    stderr: { write: (text: string) => (stderr += text), isTTY: options.isTTY },
    quiet: options.quiet,
    color: options.color,
  });
  return { out, stdout: () => stdout, stderr: () => stderr };
}

describe('a note', () => {
  it('goes to stderr, after an empty line', () => {
    const o = output();
    o.out.note('zetcert 0.2.0 is available');
    expect(o.stderr()).toBe('\nzetcert 0.2.0 is available\n');
    expect(o.stdout()).toBe('');
  });

  it('is dimmed on a terminal, unless colours are off', () => {
    const colour = output({ isTTY: true });
    colour.out.note('zetcert 0.2.0 is available');
    expect(colour.stderr()).toBe('\n\x1b[2mzetcert 0.2.0 is available\x1b[0m\n');
    const plain = output({ isTTY: true, color: false });
    plain.out.note('zetcert 0.2.0 is available');
    expect(plain.stderr()).toBe('\nzetcert 0.2.0 is available\n');
  });

  it('is hidden with -q', () => {
    const o = output({ quiet: true });
    o.out.note('zetcert 0.2.0 is available');
    expect(o.stderr()).toBe('');
  });
});
