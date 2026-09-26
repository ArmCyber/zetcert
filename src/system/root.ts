let fake: boolean | undefined;

export function isRoot(): boolean {
  return fake ?? process.getuid?.() === 0;
}

/** Pretends to run as root, or not. Tests only; `undefined` restores the real check. */
export function setIsRoot(value: boolean | undefined): void {
  fake = value;
}
