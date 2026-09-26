// Edits to config.yml go through yaml's document API, so the user's comments stay.
import { type Document, isMap, isScalar, isSeq, type Pair, YAMLMap, type YAMLSeq } from 'yaml';
import { UserError } from '../system/errors';
import { writeFileAtomic } from '../system/fs';
import { type LoadedConfig, parseConfig } from './config';

type Commented = { commentBefore?: string | null; comment?: string | null };

function isEmpty(node: unknown): boolean {
  return node === null || node === undefined || (isScalar(node) && (node.value === null || node.value === undefined));
}

function keyOf(pair: Pair): unknown {
  return isScalar(pair.key) ? pair.key.value : pair.key;
}

export class ConfigEditor {
  private readonly doc: Document;
  /** Certificates whose entry stays even when it has no options left (e.g. one just created). */
  readonly keep = new Set<string>();

  constructor(private readonly loaded: LoadedConfig) {
    this.doc = loaded.doc;
  }

  /** The map at `keys`, created (keeping comments) where it is missing or empty. */
  private mapAt(keys: string[]): YAMLMap {
    if (isEmpty(this.doc.contents)) this.doc.contents = new YAMLMap() as never;
    let node: unknown = this.doc.contents;
    for (const [i, key] of keys.entries()) {
      if (!isMap(node)) throw new UserError(`${this.loaded.path}: ${keys.slice(0, i).join('.')} is not a map`);
      // `certs: {}` (e.g. after the last certificate was deleted) would put new entries on one line.
      if (node.flow && node.items.length === 0) node.flow = false;
      const pair = node.items.find((p) => keyOf(p) === key);
      if (!pair) {
        const child = new YAMLMap();
        node.add(this.doc.createPair(key, child));
        node = child;
      } else if (isEmpty(pair.value)) {
        const child = new YAMLMap();
        const old = pair.value as Commented | null;
        (child as Commented).commentBefore = old?.commentBefore;
        (child as Commented).comment = old?.comment;
        pair.value = child;
        node = child;
      } else {
        node = pair.value;
      }
    }
    if (!isMap(node)) throw new UserError(`${this.loaded.path}: ${keys.join('.')} is not a map`);
    return node;
  }

  /** Makes sure the map at `keys` exists, e.g. a certificate's entry without options. */
  ensureMap(keys: string[]): void {
    this.mapAt(keys);
  }

  /** Sets a scalar value, e.g. set(['certs', 'mail', 'dns'], 'cf-main'). */
  set(keys: string[], value: string): void {
    const map = this.mapAt(keys.slice(0, -1));
    const key = keys[keys.length - 1] as string;
    const pair = map.items.find((p) => keyOf(p) === key);
    if (pair && isScalar(pair.value)) pair.value.value = value;
    else map.set(key, value);
  }

  /** Replaces a list, e.g. the email or a certificate's deploy commands. */
  setList(keys: string[], values: string[]): void {
    const seq = this.seqAt(keys);
    seq.items = values.map((v) => this.doc.createNode(v));
  }

  addToList(keys: string[], value: string): void {
    const seq = this.seqAt(keys);
    if (!seq.items.some((item) => isScalar(item) && item.value === value)) seq.add(this.doc.createNode(value));
  }

  removeFromList(keys: string[], value: string): void {
    const node = this.doc.getIn(keys, true);
    if (!isSeq(node)) return;
    node.items = node.items.filter((item) => !(isScalar(item) && item.value === value));
    if (node.items.length === 0) this.delete(keys);
  }

  delete(keys: string[]): void {
    const parentKeys = keys.slice(0, -1);
    const parent = parentKeys.length === 0 ? this.doc.contents : this.doc.getIn(parentKeys, true);
    if (!isMap(parent)) return;
    parent.delete(keys[keys.length - 1]);
    // Leave no empty `certs.<cert>:` behind, unless `keep` asks for it.
    if (parentKeys.length > 0 && parent.items.length === 0 && parentKeys[0] === 'certs' && parentKeys.length === 2 && !this.keep.has(parentKeys[1] as string)) {
      this.delete(parentKeys);
    }
  }

  private seqAt(keys: string[]): YAMLSeq {
    const map = this.mapAt(keys.slice(0, -1));
    const key = keys[keys.length - 1] as string;
    const pair = map.items.find((p) => keyOf(p) === key);
    if (pair && isSeq(pair.value)) return pair.value;
    const seq = this.doc.createNode([]) as YAMLSeq;
    if (pair) pair.value = seq;
    else map.add(this.doc.createPair(key, seq));
    return seq;
  }

  /** The config text after the edits; throws if the result isn't a valid config. */
  text(): string {
    const text = this.doc.toString();
    parseConfig(text, this.loaded.path);
    return text;
  }

  /** Writes the file (mode 0600) and returns the config as it is now. */
  save(): LoadedConfig {
    const text = this.text();
    writeFileAtomic(this.loaded.path, text, 0o600);
    return parseConfig(text, this.loaded.path);
  }
}
