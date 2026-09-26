// Block parser: turns tokens into directives that keep their file:line.
import type { Loc } from '../system/loc';
import { SyntaxError, type Token, tokenize } from './lexer';

export interface Directive extends Loc {
  name: string;
  args: string[];
  /** The directives inside `{ … }`. */
  block?: Directive[];
  /** The Lua code of a `*_by_lua_block`. */
  lua?: string;
  /** For `include`: the files it brought in, filled in by the include resolver. */
  include?: IncludedFile[];
  /** For `include`: the absolute path or pattern it names. */
  target?: string;
}

export interface IncludedFile {
  path: string;
  directives: Directive[];
}

export class ParseError extends Error {
  constructor(
    message: string,
    readonly loc: Loc,
  ) {
    super(`${loc.file}:${loc.line}: ${message}`);
  }
}

export function parse(text: string, file: string): Directive[] {
  let tokens: Token[];
  try {
    tokens = tokenize(text);
  } catch (err) {
    if (err instanceof SyntaxError) throw new ParseError(err.message, { file, line: err.line });
    throw err;
  }
  let pos = 0;
  let lastLine = 1;

  const block = (depth: number): Directive[] => {
    const list: Directive[] = [];
    let words: { value: string; line: number }[] = [];
    const directive = (): Directive => {
      const [first, ...rest] = words;
      words = [];
      if (!first) throw new ParseError('directive without a name', { file, line: lastLine });
      return { name: first.value, args: rest.map((w) => w.value), file, line: first.line };
    };
    while (pos < tokens.length) {
      const token = tokens[pos++] as Token;
      lastLine = token.line;
      if (token.type === 'word') {
        words.push(token);
      } else if (token.type === ';') {
        list.push(directive());
      } else if (token.type === '{') {
        const d = directive();
        const next = tokens[pos];
        if (next?.type === 'lua') {
          d.lua = next.value;
          pos += 2; // the Lua code and its closing `}`
        } else {
          d.block = block(depth + 1);
        }
        list.push(d);
      } else if (token.type === '}') {
        if (depth === 0) throw new ParseError('unexpected "}"', { file, line: token.line });
        return list;
      }
    }
    if (words.length > 0) throw new ParseError('unexpected end of file, expecting ";" or "}"', { file, line: lastLine });
    if (depth > 0) throw new ParseError('unexpected end of file, expecting "}"', { file, line: lastLine });
    return list;
  };

  return block(0);
}
