// Reading certbot's output: names the CA rejected, "not yet due" and "already running".

export interface RejectedName {
  name: string;
  reason: string;
}

/**
 * Names the CA rejected: failed challenges (`Domain:`/`Type:`/`Detail:` blocks; certbot 5 says
 * `Identifier:` instead of `Domain:`) and names refused when the order is created
 * (`Cannot issue for "name": reason`).
 */
export function parseRejected(output: string): RejectedName[] {
  const rejected = new Map<string, string>();
  const block = /^\s*(?:Domain|Identifier):\s*(\S+)\s*\n\s*Type:\s*(.*?)\s*\n\s*Detail:\s*(.*)$/gm;
  for (const m of output.matchAll(block)) {
    const [, name = '', type = '', detail = ''] = m;
    rejected.set(name.toLowerCase(), `${type}: ${detail.trim()}`);
  }
  const order = /Cannot issue for "([^"]+)": ([^;\n]+)/g;
  for (const m of output.matchAll(order)) {
    const [, name = '', reason = ''] = m;
    if (!rejected.has(name.toLowerCase())) rejected.set(name.toLowerCase(), reason.trim());
  }
  return [...rejected.entries()].map(([name, reason]) => ({ name, reason }));
}

export function isNotDue(output: string): boolean {
  return output.includes('Certificate not yet due for renewal');
}

export function isBusy(output: string): boolean {
  return output.includes('Another instance of Certbot is already running');
}

/** The lines of certbot's output worth showing when it fails, without its boilerplate. */
export function failureSummary(output: string): string {
  const skip = [/^Saving debug log/, /^Ask for help or search/, /^- - - /, /^\s*$/, /^Hint: /];
  return output
    .split('\n')
    .filter((line) => !skip.some((re) => re.test(line)))
    .slice(-12)
    .join('\n')
    .trim();
}
