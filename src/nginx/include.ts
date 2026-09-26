// Loads the nginx config from its main file and follows `include` everywhere, like nginx does:
// relative paths are relative to the main config's directory, globs are expanded in sorted order.
// A missing file is recorded instead of aborting; a syntax error or an include cycle aborts.
import path from 'node:path';
import type { Loc } from '../system/loc';
import { UserError } from '../system/errors';
import { entryExists, isDirectory, listDir, readText } from '../system/fs';
import { type Directive, ParseError, parse } from './parser';

export interface MissingInclude extends Loc {
  /** The file that doesn't exist, as an absolute path. */
  path: string;
}

export interface NginxConfig {
  main: string;
  directives: Directive[];
  /** Every file read, in order. */
  files: string[];
  missing: MissingInclude[];
}

const GLOB = /[*?[]/;

function globToRegExp(segment: string): RegExp {
  let re = '';
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i] as string;
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[') {
      const end = segment.indexOf(']', i + 2);
      if (end === -1) re += '\\[';
      else {
        let set = segment.slice(i + 1, end);
        if (set.startsWith('!')) set = `^${set.slice(1)}`;
        re += `[${set.replace(/\\/g, '\\\\')}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/** Expands a glob like glob(3) without GLOB_PERIOD: wildcards don't match a leading dot. */
export function expandGlob(pattern: string): string[] {
  const segments = pattern.split('/').filter(Boolean);
  let paths = ['/'];
  for (const [i, segment] of segments.entries()) {
    const last = i === segments.length - 1;
    const next: string[] = [];
    for (const dir of paths) {
      if (!GLOB.test(segment)) {
        next.push(path.join(dir, segment));
        continue;
      }
      const re = globToRegExp(segment);
      for (const name of listDir(dir)) {
        if (name.startsWith('.') && !segment.startsWith('.')) continue;
        if (re.test(name)) next.push(path.join(dir, name));
      }
    }
    paths = last ? next : next.filter((p) => isDirectory(p));
  }
  // Like glob(3), every matching directory entry counts, dangling links and directories too.
  return paths.filter((p) => entryExists(p)).sort();
}

export function loadNginxConfig(main: string): NginxConfig {
  const prefix = path.dirname(main);
  const result: NginxConfig = { main, directives: [], files: [], missing: [] };

  const load = (file: string, stack: string[], from?: Loc): Directive[] => {
    if (stack.includes(file)) {
      throw new ParseError(`include cycle: ${[...stack, file].join(' → ')}`, from ?? { file, line: 1 });
    }
    const text = readText(file);
    if (text === undefined) {
      if (!from) throw new UserError(`the nginx config ${file} doesn't exist (nginx.config in the zetcert config)`);
      throw new ParseError(`can't read ${file}`, from);
    }
    result.files.push(file);
    const directives = parse(text, file);
    resolve(directives, [...stack, file]);
    return directives;
  };

  const resolve = (directives: Directive[], stack: string[]): void => {
    for (const d of directives) {
      if (d.block) resolve(d.block, stack);
      if (d.name !== 'include') continue;
      if (d.args.length !== 1) throw new ParseError('include takes one file or pattern', d);
      const target = path.resolve(prefix, d.args[0] as string);
      d.target = target;
      if (GLOB.test(target)) {
        d.include = [];
        for (const file of expandGlob(target)) {
          // nginx fails on these too: a directory can't be read, a dangling link can't be opened.
          if (isDirectory(file)) throw new ParseError(`${file} is a directory, which nginx can't include`, d);
          if (readText(file) === undefined) result.missing.push({ path: file, file: d.file, line: d.line });
          else d.include.push({ path: file, directives: load(file, stack, d) });
        }
      } else if (isDirectory(target)) {
        throw new ParseError(`${target} is a directory, which nginx can't include`, d);
      } else if (readText(target) === undefined) {
        d.include = [];
        result.missing.push({ path: target, file: d.file, line: d.line });
      } else {
        d.include = [{ path: target, directives: load(target, stack, d) }];
      }
    }
  };

  result.directives = load(main, []);
  return result;
}
