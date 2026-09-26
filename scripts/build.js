// Bundles the CLI and every library it uses into one file, so the package has no runtime dependencies.
// `--e2e` builds the end-to-end test variant, which adds test-only code (ZETCERT_E2E).
import { chmodSync } from 'node:fs';
import process from 'node:process';
import { build } from 'esbuild';

const e2e = process.argv.includes('--e2e');
const outfile = e2e ? 'test/e2e/.build/package/dist/zetcert.cjs' : 'dist/zetcert.cjs';

await build({
  entryPoints: ['src/main.ts'],
  outfile,
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  banner: { js: '#!/usr/bin/env node' },
  define: { ZETCERT_E2E: String(e2e) },
  // Drops dead branches, such as the test-only code outside the e2e build.
  minifySyntax: true,
  logLevel: 'warning',
});

chmodSync(outfile, 0o755);
