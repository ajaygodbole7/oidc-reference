// ESLint flat config (eslint 9 style). Type-aware lint via parserOptions.project.
// React Hooks rules are enforced as errors so we catch missing deps and stale
// closures the same way the build catches type errors. no-floating-promises +
// no-misused-promises prevent the BFF client (async fetch helpers) from
// silently dropping rejections. checksVoidReturn.attributes is disabled so
// React JSX onClick={async () => ...} stays ergonomic.

import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "test-results/**",
      "playwright-report/**",
      "coverage/**",
      ".vite/**"
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: import.meta.dirname
      }
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-hooks/exhaustive-deps": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": [
        "error",
        { checksVoidReturn: { attributes: false } }
      ],
      "react-refresh/only-export-components": "warn",
      // SPEC-0001: the SPA holds zero tokens. Writing to localStorage or
      // sessionStorage anywhere in src/ is a contract violation in ANY spelling:
      // bare or window/globalThis/self-qualified, dot or bracket method call, or
      // direct property assignment. Reads stay allowed (debug tooling). Alias
      // writes (const s = localStorage; s.setItem(...)) are not statically
      // catchable here and are caught by the e2e no-token-in-browser proof.
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "MemberExpression[object.name=/^(localStorage|sessionStorage)$/][property.name=/^(setItem|removeItem|clear)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not write to web storage."
        },
        {
          selector:
            "MemberExpression[object.name=/^(localStorage|sessionStorage)$/][property.value=/^(setItem|removeItem|clear)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not write to web storage (bracket access)."
        },
        {
          selector:
            "MemberExpression[object.type='MemberExpression'][object.property.name=/^(localStorage|sessionStorage)$/][property.name=/^(setItem|removeItem|clear)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not write to web storage (qualified access)."
        },
        {
          selector:
            "MemberExpression[object.type='MemberExpression'][object.property.name=/^(localStorage|sessionStorage)$/][property.value=/^(setItem|removeItem|clear)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not write to web storage (qualified bracket access)."
        },
        {
          selector: "AssignmentExpression[left.object.name=/^(localStorage|sessionStorage)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not assign into web storage."
        },
        {
          selector:
            "AssignmentExpression[left.object.type='MemberExpression'][left.object.property.name=/^(localStorage|sessionStorage)$/]",
          message: "SPEC-0001: the SPA holds no tokens. Do not assign into web storage (qualified)."
        },
        {
          selector: "Identifier[name='indexedDB']",
          message: "SPEC-0001: the SPA holds no tokens. Do not touch indexedDB."
        }
      ]
    }
  },
  {
    // Tests are allowed to inspect storage (assertNoBrowserTokens helper)
    // and to introspect indexedDB.databases() for the same reason.
    files: ["**/*.test.{ts,tsx}", "tests/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-syntax": "off"
    }
  },
  {
    // The flat config itself + vite config aren't part of the TS project.
    // Lint them with the non-type-aware preset to avoid parserOptions.project
    // errors.
    files: ["eslint.config.js", "scripts/**/*.{js,mjs}"],
    ...tseslint.configs.disableTypeChecked
  },
  {
    files: ["scripts/**/*.{js,mjs}"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly" }
    },
    rules: {
      // Node scripts are allowed to write to disk and console.
      "no-restricted-syntax": "off"
    }
  }
);
