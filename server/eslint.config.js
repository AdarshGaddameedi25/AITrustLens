export default [
  {
    ignores: ['node_modules/**', 'dist/**', 'coverage/**', 'uploads/**']
  },
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module'
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_|next|res|req' }],
      'no-console': 'off'
    }
  }
];
