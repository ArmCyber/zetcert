import { readFileSync, statSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { snippetContent, usesPlaceholder, writeSnippet } from '../../../src/nginx/snippets';
import { FileBatch } from '../../../src/system/files';
import { tempRoot } from '../helpers';

describe('snippets', () => {
  let root: ReturnType<typeof tempRoot>;
  beforeEach(() => (root = tempRoot()));
  afterEach(() => root.cleanup());

  it("point at certbot's files, or at the placeholder", () => {
    expect(snippetContent('store', true)).toBe(`# Managed by zetcert — do not edit. Certificate: store
ssl_certificate     /etc/letsencrypt/live/store/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/store/privkey.pem;
`);
    expect(snippetContent('store', false)).toContain('ssl_certificate     /var/lib/zetcert/placeholder/fullchain.pem;');
    expect(usesPlaceholder(snippetContent('store', false))).toBe(true);
    expect(usesPlaceholder(snippetContent('store', true))).toBe(false);
  });

  it('are written only when their content changes, with mode 0644', () => {
    const batch = new FileBatch();
    expect(writeSnippet(batch, 'a', false)).toBe(true);
    expect(writeSnippet(batch, 'a', false)).toBe(false);
    expect(statSync(root.path('/etc/nginx/zetcert/a.conf')).mode & 0o777).toBe(0o644);
    expect(writeSnippet(batch, 'a', true)).toBe(true);
    expect(batch.changed).toEqual(['/etc/nginx/zetcert/a.conf', '/etc/nginx/zetcert/a.conf']);
  });

  it('can be restored to the previous files', () => {
    root.write('/etc/nginx/zetcert/old.conf', 'previous content\n');
    const batch = new FileBatch();
    writeSnippet(batch, 'old', true);
    writeSnippet(batch, 'old', false);
    writeSnippet(batch, 'new', false);
    batch.remove('/etc/nginx/zetcert/_tls.conf');
    batch.restore();
    expect(readFileSync(root.path('/etc/nginx/zetcert/old.conf'), 'utf8')).toBe('previous content\n');
    expect(() => statSync(root.path('/etc/nginx/zetcert/new.conf'))).toThrow();
  });
});
