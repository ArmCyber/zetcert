// Discovery: which server blocks use which zetcert certificate, and with which names.
import path from 'node:path';
import { readServerName } from '../certs/names';
import { isValidName, NAME_RULE } from '../config/names';
import type { Loc } from '../system/loc';
import { formatLoc } from '../system/loc';
import { SNIPPET_DIR } from '../system/paths';
import type { MissingInclude, NginxConfig } from './include';
import type { Directive } from './parser';

export interface SnippetInclude extends Loc {
  cert: string;
  /** False when the snippet file doesn't exist yet: a new certificate. */
  exists: boolean;
}

export interface ServerName extends Loc {
  name: string;
  raw: string;
}

export interface SkippedName extends Loc {
  raw: string;
  reason: string;
  /** Shown as a warning; the others are only listed with `status -v`. */
  warn: boolean;
}

export interface Listen extends Loc {
  /** The address as written, e.g. `443`, `[::]:443`, `10.0.0.1:8443`, `unix:/run/x.sock`. */
  address: string;
  ssl: boolean;
  quic: boolean;
  proxyProtocol: boolean;
}

export interface ServerBlock extends Loc {
  names: ServerName[];
  /** This block's `server_name` values that aren't used. */
  skipped: SkippedName[];
  listens: Listen[];
  /** The zetcert snippet the block includes, directly or through nested includes. */
  snippet?: SnippetInclude;
  /** The block has an `ssl_certificate` that doesn't come from a zetcert snippet. */
  ownCertificate: boolean;
  /** The certificate the block uses: its own snippet's, or the one inherited from `http {}`. */
  cert?: string;
  inherited: boolean;
}

export interface Issue {
  message: string;
  loc: Loc;
}

export interface Discovery {
  servers: ServerBlock[];
  /** A zetcert snippet included in `http {}`, inherited by `listen … ssl` blocks without a certificate. */
  httpSnippet?: SnippetInclude;
  /** Every include of a zetcert snippet, in any context. */
  snippetIncludes: SnippetInclude[];
  /** Includes of zetcert's support files, e.g. `_tls.conf`. */
  supportIncludes: (Loc & { path: string })[];
  /** Missing include files other than zetcert snippets. */
  missing: MissingInclude[];
  /** `server_name` values that aren't used. */
  skipped: SkippedName[];
  errors: Issue[];
  warnings: Issue[];
  /** `ssl_stapling on`, useless since Let's Encrypt ended OCSP. */
  stapling: Loc[];
}

/** The certificate name if `file` is a zetcert snippet path; support files (`_…`) aren't. */
export function snippetCert(file: string): string | undefined {
  if (path.dirname(file) !== SNIPPET_DIR || !file.endsWith('.conf')) return undefined;
  const base = path.basename(file, '.conf');
  return base.startsWith('_') ? undefined : base;
}

function isSupportFile(file: string): boolean {
  return path.dirname(file) === SNIPPET_DIR && path.basename(file).startsWith('_');
}

/** The snippet includes an `include` directive makes: one per snippet file it names or matches. */
function snippetsOf(d: Directive): SnippetInclude[] {
  if (d.name !== 'include' || !d.target) return [];
  const loc = { file: d.file, line: d.line };
  if (/[*?[]/.test(d.target)) {
    return (d.include ?? []).flatMap((f) => {
      const cert = snippetCert(f.path);
      return cert ? [{ cert, exists: true, ...loc }] : [];
    });
  }
  const cert = snippetCert(d.target);
  return cert ? [{ cert, exists: (d.include ?? []).length > 0, ...loc }] : [];
}

/**
 * The directives of one block level with includes spliced in, the way nginx sees them. The
 * contents of zetcert snippets are left out: the include itself stands for the certificate.
 */
function level(directives: Directive[]): Directive[] {
  return directives.flatMap((d) => {
    if (d.name !== 'include' || !d.include || snippetsOf(d).length > 0) return [d];
    return [d, ...d.include.flatMap((f) => level(f.directives))];
  });
}

/** Every directive in every context, includes followed. */
function everywhere(directives: Directive[]): Directive[] {
  return directives.flatMap((d) => [
    d,
    ...(d.block ? everywhere(d.block) : []),
    ...(d.include ?? []).flatMap((f) => everywhere(f.directives)),
  ]);
}

export function discover(config: NginxConfig): Discovery {
  const result: Discovery = {
    servers: [],
    snippetIncludes: [],
    supportIncludes: [],
    missing: [],
    skipped: [],
    errors: [],
    warnings: [],
    stapling: [],
  };

  for (const d of everywhere(config.directives)) {
    if (d.name === 'include' && d.target) {
      const snippets = snippetsOf(d);
      if (snippets.length > 0 && /[*?[]/.test(d.target)) {
        result.warnings.push({
          message: `don't include ${SNIPPET_DIR} with a glob: include one certificate's snippet per server block`,
          loc: d,
        });
      }
      for (const s of snippets) {
        if (!isValidName(s.cert)) {
          result.errors.push({ message: `invalid certificate name "${s.cert}": ${NAME_RULE}`, loc: d });
        } else {
          result.snippetIncludes.push(s);
        }
      }
      if (isSupportFile(d.target)) result.supportIncludes.push({ path: d.target, file: d.file, line: d.line });
    }
    if (d.name === 'ssl_stapling' && d.args[0] === 'on') result.stapling.push({ file: d.file, line: d.line });
  }
  const snippetTargets = new Set(result.snippetIncludes.map((s) => `${SNIPPET_DIR}/${s.cert}.conf`));
  result.missing = config.missing.filter((m) => !snippetTargets.has(m.path) && snippetCert(m.path) === undefined);

  // A block level may include one zetcert snippet at most.
  const oneSnippet = (list: Directive[], where: string, loc: Loc): SnippetInclude | undefined => {
    const snippets = list.flatMap(snippetsOf).filter((s) => isValidName(s.cert));
    const [first, ...others] = snippets;
    if (first && others.length > 0) {
      result.errors.push({
        message: `${where} at ${formatLoc(loc)} includes ${snippets.length} zetcert certificates (${snippets
          .map((s) => `${s.cert} at ${formatLoc(s)}`)
          .join(', ')}): a server block uses one certificate`,
        loc: others[0] as SnippetInclude,
      });
    }
    return first;
  };

  for (const http of level(config.directives).filter((d) => d.name === 'http' && d.block)) {
    const httpLevel = level(http.block ?? []);
    const httpSnippet = oneSnippet(httpLevel, 'http {}', http);
    if (httpSnippet) result.httpSnippet = httpSnippet;

    for (const server of httpLevel.filter((d) => d.name === 'server' && d.block)) {
      const serverLevel = level(server.block ?? []);
      const block: ServerBlock = {
        file: server.file,
        line: server.line,
        names: [],
        skipped: [],
        listens: [],
        ownCertificate: serverLevel.some((d) => d.name === 'ssl_certificate'),
        inherited: false,
      };
      block.snippet = oneSnippet(serverLevel, 'the server block', server);
      for (const d of serverLevel) {
        if (d.name === 'listen') {
          const [address = '', ...flags] = d.args;
          block.listens.push({
            address,
            ssl: flags.includes('ssl'),
            quic: flags.includes('quic'),
            proxyProtocol: flags.includes('proxy_protocol'),
            file: d.file,
            line: d.line,
          });
        } else if (d.name === 'server_name') {
          for (const raw of d.args) {
            const read = readServerName(raw);
            if ('names' in read) {
              for (const name of read.names) block.names.push({ name, raw, file: d.file, line: d.line });
            } else {
              const skipped = { raw, reason: read.skip, warn: read.warn, file: d.file, line: d.line };
              block.skipped.push(skipped);
              result.skipped.push(skipped);
            }
          }
        }
      }
      if (block.snippet) {
        block.cert = block.snippet.cert;
      } else if (
        result.httpSnippet &&
        !block.ownCertificate &&
        block.listens.some((l) => l.ssl || l.quic)
      ) {
        block.cert = result.httpSnippet.cert;
        block.inherited = true;
      }
      result.servers.push(block);
    }
  }
  return result;
}
