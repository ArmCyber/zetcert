// The certificates zetcert manages and the names each one should hold.
import { type Challenge, type Config, certConfig, type KeyType } from '../config/config';
import { isValidName, wildcardDomain } from '../config/names';
import type { Discovery, ServerBlock, SkippedName } from '../nginx/discovery';
import type { Loc } from '../system/loc';
import { formatLoc } from '../system/loc';
import { isWildcard, isWithin, normalizeCertName, parentOf } from './names';

export const MAX_NAMES = 100;
export const WARN_NAMES = 25;

export type Kind = 'wildcard' | 'regular';
export type Validation = 'http' | 'dns';

export type NameSource =
  /** A `server_name`; `raw` is the value as written, which may differ from the name it led to. */
  | { type: 'nginx'; raw: string; loc: Loc }
  | { type: 'config' }
  /** `D` and `*.D` of a `wildcard.D` certificate. */
  | { type: 'wildcard' };

export interface WantedName {
  name: string;
  sources: NameSource[];
}

export interface Problem {
  message: string;
  loc?: Loc;
  code?: 'outside-domain' | 'too-many-names';
}

export interface CertModel {
  cert: string;
  kind: Kind;
  /** `D` for `wildcard.D`. */
  domain?: string;
  /** The names the certificate should hold, in the order given to certbot. */
  names: WantedName[];
  /** Names found in nginx or the config that the certificate doesn't need or can't take. */
  dropped: { name: string; reason: string; sources: NameSource[] }[];
  validation: Validation;
  challenge: Challenge;
  keyType: KeyType;
  dnsAccount?: string;
  deploy: string[];
  servers: ServerBlock[];
  /** `server_name` values of its server blocks that aren't used. */
  skipped: SkippedName[];
  /** Included somewhere in nginx. */
  included: boolean;
  /** Included, but the snippet file doesn't exist yet. */
  newInclude: boolean;
  inConfig: boolean;
  snippetExists: boolean;
  /** No include left and not in the config. */
  unused: boolean;
  errors: Problem[];
  warnings: Problem[];
}

/** Orders names the way certbot gets them: by domain, parents before children, `*.x` right after `x`. */
export function compareNames(a: string, b: string): number {
  const ka = a.split('.').reverse();
  const kb = b.split('.').reverse();
  for (let i = 0; i < Math.min(ka.length, kb.length); i++) {
    const x = ka[i] as string;
    const y = kb[i] as string;
    if (x !== y) return x < y ? -1 : 1;
  }
  return ka.length - kb.length;
}

function describeSource(source: NameSource): string {
  if (source.type === 'nginx') return `${source.raw} at ${formatLoc(source.loc)}`;
  return source.type === 'config' ? 'the config' : 'the certificate name';
}

interface Input {
  name: string;
  source: NameSource;
}

class NameSet {
  private readonly map = new Map<string, NameSource[]>();

  add(name: string, source: NameSource): void {
    const sources = this.map.get(name);
    if (sources) sources.push(source);
    else this.map.set(name, [source]);
  }

  has(name: string): boolean {
    return this.map.has(name);
  }

  delete(name: string): NameSource[] {
    const sources = this.map.get(name) ?? [];
    this.map.delete(name);
    return sources;
  }

  names(): string[] {
    return [...this.map.keys()];
  }

  list(): WantedName[] {
    return [...this.map.entries()]
      .map(([name, sources]) => ({ name, sources }))
      .sort((a, b) => compareNames(a.name, b.name));
  }
}

function wildcardNames(domain: string, inputs: Input[], model: CertModel): NameSet {
  const set = new NameSet();
  set.add(domain, { type: 'wildcard' });
  set.add(`*.${domain}`, { type: 'wildcard' });
  for (const { name, source } of inputs) {
    if (name === domain || name === `*.${domain}`) {
      set.add(name, source);
    } else if (!isWithin(name, domain)) {
      model.dropped.push({ name, reason: `outside ${domain}: it belongs in another certificate`, sources: [source] });
      model.warnings.push({
        message: `${name} (${describeSource(source)}) is outside ${domain}, so ${model.cert} doesn't cover it: it belongs in another certificate`,
        loc: source.type === 'nginx' ? source.loc : undefined,
        code: 'outside-domain',
      });
    } else if (isWildcard(name) || parentOf(name) !== domain) {
      // `*.x.D` is kept as it is; a deeper name `a.x.D` needs `*.x.D`.
      set.add(isWildcard(name) ? name : `*.${parentOf(name)}`, source);
    } else {
      // `x.D` is covered by `*.D`.
      set.add(`*.${domain}`, source);
    }
  }
  return set;
}

function regularNames(inputs: Input[], model: CertModel): NameSet {
  const set = new NameSet();
  for (const { name, source } of inputs) set.add(name, source);
  for (const name of set.names()) {
    const wildcard = `*.${parentOf(name)}`;
    if (!isWildcard(name) && set.has(wildcard)) {
      model.dropped.push({ name, reason: `covered by ${wildcard}`, sources: set.delete(name) });
    }
  }
  return set;
}

export interface ModelInput {
  config: Config;
  discovery: Discovery;
  /** Certificates that have a snippet file in /etc/nginx/zetcert. */
  snippets: string[];
}

export function buildModel({ config, discovery, snippets }: ModelInput): CertModel[] {
  const included = new Set(discovery.snippetIncludes.map((s) => s.cert));
  const existing = new Set(snippets.filter(isValidName));
  const all = new Set([...included, ...existing, ...Object.keys(config.certs)]);

  return [...all].sort().map((cert) => {
    const options = certConfig(config, cert);
    const domain = wildcardDomain(cert);
    const servers = discovery.servers.filter((s) => s.cert === cert);
    const model: CertModel = {
      cert,
      kind: domain === undefined ? 'regular' : 'wildcard',
      domain,
      names: [],
      dropped: [],
      validation: 'http',
      challenge: options.challenge,
      keyType: options.key_type ?? config.key_type,
      dnsAccount: options.dns,
      deploy: options.deploy,
      servers,
      skipped: servers.flatMap((s) => s.skipped),
      included: included.has(cert),
      newInclude: discovery.snippetIncludes.some((s) => s.cert === cert && !s.exists) && !existing.has(cert),
      inConfig: cert in config.certs,
      snippetExists: existing.has(cert),
      unused: !included.has(cert) && !(cert in config.certs),
      errors: [],
      warnings: [],
    };

    const exclude = new Set(options.exclude);
    const inputs: Input[] = [
      ...servers.flatMap((s) =>
        s.names.map((n) => ({ name: n.name, source: { type: 'nginx', raw: n.raw, loc: { file: n.file, line: n.line } } as NameSource })),
      ),
      ...options.names.map((name) => ({ name, source: { type: 'config' } as NameSource })),
    ];
    for (const input of inputs.filter((i) => exclude.has(i.name))) {
      model.dropped.push({ name: input.name, reason: 'excluded in the config', sources: [input.source] });
    }
    const kept = inputs.filter((i) => !exclude.has(i.name));

    if (domain !== undefined && normalizeCertName(domain) !== domain) {
      model.errors.push({ message: `${cert}: ${domain} is not a valid domain for a wildcard certificate` });
    } else {
      const names = (domain !== undefined ? wildcardNames(domain, kept, model) : regularNames(kept, model)).list();
      // `exclude` also removes a name the rules made, like *.x.D.
      for (const n of names.filter((x) => exclude.has(x.name))) {
        model.dropped.push({ name: n.name, reason: 'excluded in the config', sources: n.sources });
      }
      model.names = names.filter((x) => !exclude.has(x.name));
      for (const e of exclude) {
        if (!inputs.some((i) => i.name === e) && !names.some((n) => n.name === e)) {
          model.warnings.push({ message: `exclude: ${e} isn't one of ${cert}'s names` });
        }
      }
    }

    const wildcard = model.names.find((n) => isWildcard(n.name));
    if (model.kind === 'regular' && model.challenge === 'http' && wildcard) {
      const source = wildcard.sources[0];
      model.errors.push({
        message: `challenge: http can't validate the wildcard name ${wildcard.name}${source ? ` (${describeSource(source)})` : ''}: use auto or dns`,
        loc: source?.type === 'nginx' ? source.loc : undefined,
      });
    }
    model.validation = model.kind === 'wildcard' || wildcard || model.challenge === 'dns' ? 'dns' : 'http';

    if (model.names.length > MAX_NAMES) {
      model.errors.push({
        message: `${model.names.length} names: Let's Encrypt allows ${MAX_NAMES} per certificate, so split the certificate`,
      });
    } else if (model.names.length > WARN_NAMES) {
      model.warnings.push({
        message: `${model.names.length} names: more than ${WARN_NAMES}, which Let's Encrypt's newer profiles allow; consider splitting the certificate`,
        code: 'too-many-names',
      });
    }
    return model;
  });
}
