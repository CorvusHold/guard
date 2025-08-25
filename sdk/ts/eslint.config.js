/* eslint-env node */
import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import vitestPlugin from 'eslint-plugin-vitest';

export default [
  // Ignore build output
  { ignores: ['dist/**', 'node_modules/**'] },

  // Base JS recommended rules
  js.configs.recommended,

  // TypeScript files
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: 2020, sourceType: 'module' },
    },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      '@typescript-eslint/explicit-module-boundary-types': 'off',
    },
  },

  // Test files (Vitest)
  {
    files: ['**/*.test.ts', '**/*.test.tsx'],
    plugins: { vitest: vitestPlugin },
    languageOptions: {
      // Explicit vitest globals
      globals: {
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly',
      },
    },
    rules: {},
  },
];
