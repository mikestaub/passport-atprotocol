module.exports = {
  parserOptions: { project: './tsconfig.json', tsconfigRootDir: __dirname },
  rules: {
    'arca/no-default-export': 'off',
    'promise/param-names': 'off',
  },
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
};
