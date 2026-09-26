/** A place in a file, reported as file:line. */
export interface Loc {
  file: string;
  line: number;
}

export function formatLoc(loc: Loc): string {
  return `${loc.file}:${loc.line}`;
}
