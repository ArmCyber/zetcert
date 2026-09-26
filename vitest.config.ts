import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { ZETCERT_E2E: 'false' },
  test: {
    include: ['test/unit/**/*.test.ts'],
  },
});
