// nginx config tokenizer, following nginx's own rules (ngx_conf_read_token):
// - `#` starts a comment only where a new token would start;
// - single and double quotes, with \" \' \\ \t \r \n escapes (other backslashes are kept);
// - a word ends at whitespace, `;` or `{`, but not at `}`;
// - `${var}`: the `{` after `$` doesn't open a block;
// - `*_by_lua_block { … }` bodies are Lua code, read as one raw token.

export type Token =
  | { type: 'word'; value: string; line: number }
  | { type: ';' | '{' | '}'; line: number }
  | { type: 'lua'; value: string; line: number };

export class SyntaxError extends Error {
  constructor(
    message: string,
    readonly line: number,
  ) {
    super(message);
  }
}

const SPACE = new Set([' ', '\t', '\r', '\n']);

function unescape(raw: string): string {
  return raw.replace(/\\(["'\\tnr])/g, (_, c: string) => ({ t: '\t', n: '\n', r: '\r' })[c] ?? c);
}

/** Reads a Lua block body from `start` (just after `{`) to its closing `}`. */
function readLua(text: string, start: number, startLine: number): { value: string; end: number; line: number } {
  let i = start;
  let line = startLine;
  let depth = 1;
  const longBracket = (at: number): number => {
    // `[`, any number of `=`, `[`: returns the number of `=`, or -1.
    if (text[at] !== '[') return -1;
    let j = at + 1;
    while (text[j] === '=') j++;
    return text[j] === '[' ? j - at - 1 : -1;
  };
  const skipLong = (at: number, level: number): number => {
    const close = `]${'='.repeat(level)}]`;
    const end = text.indexOf(close, at);
    if (end === -1) throw new SyntaxError('unexpected end of file in a Lua block', line);
    for (let k = at; k < end; k++) if (text[k] === '\n') line++;
    return end + close.length;
  };
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\n') {
      line++;
      i++;
    } else if (ch === '-' && text[i + 1] === '-') {
      const level = longBracket(i + 2);
      if (level >= 0) {
        i = skipLong(i + 4 + level, level);
      } else {
        while (i < text.length && text[i] !== '\n') i++;
      }
    } else if (ch === '"' || ch === "'") {
      i++;
      while (i < text.length && text[i] !== ch) {
        if (text[i] === '\\') i++;
        if (text[i] === '\n') line++;
        i++;
      }
      i++;
    } else if (ch === '[' && longBracket(i) >= 0) {
      const level = longBracket(i);
      i = skipLong(i + 2 + level, level);
    } else if (ch === '{') {
      depth++;
      i++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0) return { value: text.slice(start, i), end: i + 1, line };
      i++;
    } else {
      i++;
    }
  }
  throw new SyntaxError('unexpected end of file in a Lua block', line);
}

export function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  // Words in the current statement, and its first word (the directive name).
  let words = 0;
  let directive = '';

  while (i < text.length) {
    const ch = text[i] as string;
    if (ch === '\n') {
      line++;
      i++;
      continue;
    }
    if (SPACE.has(ch)) {
      i++;
      continue;
    }
    if (ch === '#') {
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (ch === ';' || ch === '{') {
      if (words === 0) throw new SyntaxError(`unexpected "${ch}"`, line);
      tokens.push({ type: ch, line });
      i++;
      if (ch === '{' && directive.endsWith('_by_lua_block')) {
        const lua = readLua(text, i, line);
        tokens.push({ type: 'lua', value: lua.value, line });
        tokens.push({ type: '}', line: lua.line });
        i = lua.end;
        line = lua.line;
      }
      words = 0;
      continue;
    }
    if (ch === '}') {
      if (words !== 0) throw new SyntaxError('unexpected "}"', line);
      tokens.push({ type: '}', line });
      i++;
      continue;
    }

    const startLine = line;
    let raw = '';
    if (ch === '"' || ch === "'") {
      i++;
      for (;;) {
        if (i >= text.length) throw new SyntaxError('unexpected end of file, expecting ";" or "}"', startLine);
        const c = text[i] as string;
        if (c === '\\' && i + 1 < text.length) {
          raw += c + text[i + 1];
          if (text[i + 1] === '\n') line++;
          i += 2;
          continue;
        }
        if (c === ch) break;
        if (c === '\n') line++;
        raw += c;
        i++;
      }
      i++;
      const next = text[i];
      if (next !== undefined && !SPACE.has(next) && next !== ';' && next !== '{' && next !== ')') {
        throw new SyntaxError(`unexpected "${next}"`, line);
      }
    } else {
      while (i < text.length) {
        const c = text[i] as string;
        if (SPACE.has(c) || c === ';' || c === '{') {
          // `${` is part of a variable, not a block.
          if (c === '{' && raw.endsWith('$') && !raw.endsWith('\\$')) {
            raw += c;
            i++;
            continue;
          }
          break;
        }
        if (c === '\\' && i + 1 < text.length) {
          raw += c + text[i + 1];
          if (text[i + 1] === '\n') line++;
          i += 2;
          continue;
        }
        raw += c;
        i++;
      }
    }
    const value = unescape(raw);
    if (words === 0) directive = value;
    words++;
    tokens.push({ type: 'word', value, line: startLine });
  }
  return tokens;
}
