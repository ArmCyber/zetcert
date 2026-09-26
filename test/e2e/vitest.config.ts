import { BaseSequencer, type TestSpecification } from 'vitest/node';
import { defineConfig } from 'vitest/config';

/** The files build on each other: 1-http, 2-dns, 3-commands. */
class ByName extends BaseSequencer {
  override async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    return [...files].sort((a, b) => a.moduleId.localeCompare(b.moduleId));
  }
}

export default defineConfig({
  define: { ZETCERT_E2E: 'false' },
  test: {
    include: ['test/e2e/**/*.test.ts'],
    globalSetup: ['test/e2e/global-setup.ts'],
    fileParallelism: false,
    sequence: { sequencer: ByName },
    testTimeout: 300_000,
    hookTimeout: 900_000,
  },
});
