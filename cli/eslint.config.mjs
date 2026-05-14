import js from '@eslint/js';

const nodeGlobals = {
  Buffer: 'readonly',
  ReadableStream: 'readonly',
  console: 'readonly',
  process: 'readonly',
  setImmediate: 'readonly',
  setTimeout: 'readonly',
};

export default [
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: nodeGlobals,
    },
  },
];
