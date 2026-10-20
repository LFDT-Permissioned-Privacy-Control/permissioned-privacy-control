module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
  },
  overrides: [
    {
      // Node-based build/config files use CommonJS (require) and run in Node,
      // not the browser. Give them the node env so `require`/`module` resolve.
      files: ['*.config.js', '*.config.cjs', 'postcss.config.js', 'tailwind.config.js'],
      env: { node: true, browser: false },
    },
    {
      // Test files and test-utils are never part of the Vite/React Fast Refresh
      // graph (they are run by Vitest, not the dev server), so the
      // react-refresh "only export components" constraint does not apply. Test
      // helpers intentionally co-export render functions, mock contexts and
      // re-exports. Turn the rule off for tests rather than scattering
      // per-line disables across every helper.
      files: [
        '**/__tests__/**/*.{ts,tsx}',
        '**/*.test.{ts,tsx}',
        'src/test/**/*.{ts,tsx}',
      ],
      rules: {
        'react-refresh/only-export-components': 'off',
      },
    },
  ],
}
