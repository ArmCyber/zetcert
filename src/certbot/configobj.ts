// A reader for the ConfigObj format of certbot's renewal files (/etc/letsencrypt/renewal/<cert>.conf):
// `key = value` lines, `[section]` and `[[subsection]]`, comments, quoted values and comma lists.

export type Value = string | string[];

export interface Section {
  values: Record<string, Value>;
  sections: Record<string, Section>;
}

function unquote(item: string): string {
  const t = item.trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) return t.slice(1, -1);
  return t;
}

/** Splits at commas outside quotes. */
function splitList(value: string): string[] {
  const items: string[] = [];
  let current = '';
  let quote = '';
  for (const c of value) {
    if (quote) {
      if (c === quote) quote = '';
      current += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      current += c;
    } else if (c === ',') {
      items.push(current);
      current = '';
    } else {
      current += c;
    }
  }
  items.push(current);
  return items;
}

/** Removes a ` # comment` that isn't inside quotes. */
function stripComment(value: string): string {
  let quote = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#') {
      return value.slice(0, i);
    }
  }
  return value;
}

function parseValue(raw: string): Value {
  const value = stripComment(raw).trim();
  const items = splitList(value);
  if (items.length === 1) return unquote(value);
  // A comma outside quotes makes a list: `a, b`; `a,` is a list of one item and `,` an empty one.
  const trimmed = items.map((i) => i.trim());
  if (trimmed[trimmed.length - 1] === '') trimmed.pop();
  return trimmed.filter((i) => i !== '').map(unquote);
}

export function parseConfigObj(text: string): Section {
  const root: Section = { values: {}, sections: {} };
  // The section at each nesting depth: 0 is the top level.
  const stack: Section[] = [root];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] as string).trim();
    if (line === '' || line.startsWith('#')) continue;
    const header = /^(\[+)\s*([^\]]+?)\s*(\]+)\s*(#.*)?$/.exec(line);
    if (header) {
      const depth = (header[1] as string).length;
      const parent = stack[Math.min(depth - 1, stack.length - 1)] as Section;
      const section: Section = { values: {}, sections: {} };
      parent.sections[header[2] as string] = section;
      stack.length = depth;
      stack[depth] = section;
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = unquote(line.slice(0, eq));
    let raw = line.slice(eq + 1).trim();
    // Triple-quoted values may span lines.
    const triple = raw.startsWith('"""') ? '"""' : raw.startsWith("'''") ? "'''" : '';
    if (triple) {
      let body = raw.slice(3);
      while (!body.includes(triple) && i + 1 < lines.length) body += `\n${lines[++i]}`;
      raw = JSON.stringify(body.slice(0, body.indexOf(triple)));
      (stack[stack.length - 1] as Section).values[key] = JSON.parse(raw) as string;
      continue;
    }
    (stack[stack.length - 1] as Section).values[key] = parseValue(raw);
  }
  return root;
}
