import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

export default defineConfig([
  { ignores: ['dist/', 'coverage/', 'test/e2e/.build/'] },
  js.configs.recommended,
  tseslint.configs.recommended,
]);
