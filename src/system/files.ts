// Writes generated files as a batch that can be undone: `sync` restores the previous files when
// `nginx -t` fails after writing them.
import { readText, removeFile, writeFileAtomic } from './fs';

interface Previous {
  path: string;
  /** The content before the first write in this batch; undefined when the file didn't exist. */
  content: string | undefined;
  mode: number;
}

export class FileBatch {
  private readonly previous = new Map<string, Previous>();
  /** Files written or removed, in order. */
  readonly changed: string[] = [];

  /** Writes the file if its content differs. Returns whether it changed. */
  write(path: string, content: string, mode: number): boolean {
    const current = readText(path);
    if (current === content) return false;
    if (!this.previous.has(path)) this.previous.set(path, { path, content: current, mode });
    writeFileAtomic(path, content, mode);
    this.changed.push(path);
    return true;
  }

  /** Removes the file if it exists. Returns whether it did. */
  remove(path: string, mode = 0o644): boolean {
    const current = readText(path);
    if (current === undefined) return false;
    if (!this.previous.has(path)) this.previous.set(path, { path, content: current, mode });
    removeFile(path);
    this.changed.push(path);
    return true;
  }

  /** Puts every file back as it was before this batch. */
  restore(): void {
    for (const p of this.previous.values()) {
      if (p.content === undefined) removeFile(p.path);
      else writeFileAtomic(p.path, p.content, p.mode);
    }
    this.previous.clear();
  }
}
