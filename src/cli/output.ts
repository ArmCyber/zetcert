// Everything zetcert prints goes through an Output: normal output on stdout, warnings and errors on
// stderr, so `--json` output and the DNS hook's stdout stay clean.

export interface Loc {
  file: string;
  line: number;
}

export function formatLoc(loc: Loc): string {
  return `${loc.file}:${loc.line}`;
}

export interface Writer {
  write(text: string): unknown;
  isTTY?: boolean;
}

export interface OutputOptions {
  stdout?: Writer;
  stderr?: Writer;
  color?: boolean;
  quiet?: boolean;
  verbose?: boolean;
}

// eslint-disable-next-line no-control-regex -- matches ANSI colour codes
const ANSI = /\x1b\[[0-9;]*m/g;

export function visibleLength(text: string): number {
  return text.replace(ANSI, '').length;
}

export class Output {
  readonly stdout: Writer;
  readonly stderr: Writer;
  readonly color: boolean;
  /** Colours for warnings and errors, which go to stderr. */
  private readonly colorErr: boolean;
  readonly quiet: boolean;
  readonly verbose: boolean;

  constructor(options: OutputOptions = {}) {
    this.stdout = options.stdout ?? process.stdout;
    this.stderr = options.stderr ?? process.stderr;
    this.color = (options.color ?? true) && this.stdout.isTTY === true;
    this.colorErr = (options.color ?? true) && this.stderr.isTTY === true;
    this.quiet = options.quiet ?? false;
    this.verbose = options.verbose ?? false;
  }

  /** Normal output; hidden with -q. */
  info(text = ''): void {
    if (!this.quiet) this.stdout.write(`${text}\n`);
  }

  /** Output that is shown even with -q, such as `--json` data or a result asked for. */
  print(text = ''): void {
    this.stdout.write(`${text}\n`);
  }

  /** Details shown only with -v. */
  detail(text: string): void {
    if (this.verbose) this.stdout.write(`${text}\n`);
  }

  warn(text: string, loc?: Loc): void {
    const label = this.colorErr ? '\x1b[33mwarning:\x1b[0m' : 'warning:';
    this.stderr.write(`${label} ${loc ? `${formatLoc(loc)}: ` : ''}${text}\n`);
  }

  error(text: string, loc?: Loc): void {
    const label = this.colorErr ? '\x1b[31merror:\x1b[0m' : 'error:';
    this.stderr.write(`${label} ${loc ? `${formatLoc(loc)}: ` : ''}${text}\n`);
  }

  /** Columns padded to the widest cell. */
  table(header: string[], rows: string[][]): string[] {
    const widths = header.map((h, i) => Math.max(visibleLength(h), ...rows.map((r) => visibleLength(r[i] ?? ''))));
    const line = (cells: string[]) =>
      cells
        .map((cell, i) => (i === cells.length - 1 ? cell : cell + ' '.repeat((widths[i] ?? 0) - visibleLength(cell))))
        .join('  ')
        .trimEnd();
    return [this.bold(line(header)), ...rows.map(line)];
  }

  bold(text: string): string {
    return this.paint(text, '1');
  }
  dim(text: string): string {
    return this.paint(text, '2');
  }
  red(text: string): string {
    return this.paint(text, '31');
  }
  green(text: string): string {
    return this.paint(text, '32');
  }
  yellow(text: string): string {
    return this.paint(text, '33');
  }

  private paint(text: string, code: string): string {
    return this.color ? `\x1b[${code}m${text}\x1b[0m` : text;
  }
}
