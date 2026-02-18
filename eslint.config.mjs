import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';
import sonarjs from 'eslint-plugin-sonarjs';
import noSecrets from 'eslint-plugin-no-secrets';
import noUnsanitized from 'eslint-plugin-no-unsanitized';

export default tseslint.config(
  // ── Global ignores ─────────────────────────────────────────────
  {
    ignores: [
      'dist/**',
      'client/dist/**',
      'node_modules/**',
      '*.js',
      '*.mjs',
      'esbuild.config.js',
    ],
  },

  // ── Base configs ───────────────────────────────────────────────
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,

  // ── eslint-plugin-security (all files) ─────────────────────────
  security.configs.recommended,

  // ── eslint-plugin-sonarjs (all files) ──────────────────────────
  sonarjs.configs.recommended,

  // ── eslint-plugin-no-secrets (all files) ───────────────────────
  {
    plugins: { 'no-secrets': noSecrets },
    rules: {
      'no-secrets/no-secrets': ['error', { tolerance: 4.2 }],
    },
  },

  // ── Parser options for typed linting ──────────────────────────
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // ── Global rule tuning ────────────────────────────────────────
  {
    rules: {
      // detect-object-injection has an extremely high false-positive rate
      // on typed Map/object lookups. Other security rules remain active.
      'security/detect-object-injection': 'off',

      // Allow event handlers and callbacks to return promises.
      // Actual floating-promise bugs are caught by no-floating-promises.
      '@typescript-eslint/no-misused-promises': ['error', {
        checksVoidReturn: {
          arguments: false,
          attributes: false,
        },
      }],

      // Raise cognitive complexity threshold — crypto/UI rendering functions
      // are inherently complex and splitting them would reduce readability
      'sonarjs/cognitive-complexity': ['error', 30],

      // Style-level sonarjs rules — not security-relevant
      'sonarjs/no-selector-parameter': 'off',
      'sonarjs/concise-regex': 'off',
      'sonarjs/no-nested-conditional': 'off',
      'sonarjs/different-types-comparison': 'off',
      'sonarjs/deprecation': 'warn',

      // Math.random() is used for non-cryptographic jitter/reconnect delays;
      // crypto operations use Web Crypto API throughout the codebase
      'sonarjs/pseudo-random': 'off',

      // Allow underscore-prefixed unused args (common pattern for interface compliance)
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
    },
  },

  // ── Server-specific overrides ─────────────────────────────────
  {
    files: ['server/**/*.ts'],
    rules: {
      'security/detect-non-literal-fs-filename': 'error',
    },
  },

  // ── Client-specific overrides (no-unsanitized) ────────────────
  {
    files: ['client/**/*.ts'],
    plugins: { 'no-unsanitized': noUnsanitized },
    rules: {
      'no-unsanitized/method': 'error',
      'no-unsanitized/property': 'error',
    },
  },

  // ── Client storage (IndexedDB) — inherently untyped IDB API ──
  {
    files: ['client/src/storage/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/prefer-promise-reject-errors': 'off',
    },
  },

  // ── Test file relaxations ─────────────────────────────────────
  {
    files: ['tests/**/*.ts', '**/*.test.ts'],
    rules: {
      'no-secrets/no-secrets': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      'sonarjs/unused-import': 'off',
      'sonarjs/deprecation': 'off',
      'security/detect-object-injection': 'off',
    },
  },
);
