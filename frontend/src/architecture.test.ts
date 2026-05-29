// Spec-conformance tests that read source files and assert structural
// invariants ESLint can't express. Cheap (no Playwright, no jsdom render),
// fast (millis), and catches regressions the end-to-end gate would only
// catch minutes later.
//
// Pattern borrowed from ~/react-template/tests/unit/architecture.test.js.
// The contract these tests pin comes from docs/specs/SPEC-0001-core-oidc-flows.md.

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function read(rel: string): string {
  return readFileSync(path.resolve(rel), "utf-8");
}

describe("Spec conformance — frontend invariants", () => {
  describe("auth.ts (BFF client)", () => {
    const source = read("src/auth.ts");

    it("never writes to localStorage / sessionStorage / indexedDB", () => {
      // Reads are fine (none today, but allowed). Writes are the contract
      // violation: the SPA must never persist auth state of any kind.
      expect(source).not.toMatch(/localStorage\.(setItem|clear|removeItem)/);
      expect(source).not.toMatch(/sessionStorage\.(setItem|clear|removeItem)/);
      expect(source).not.toMatch(/\bindexedDB\b/);
    });

    it("every fetch carries credentials: 'include' for same-origin cookies", () => {
      const fetchCalls = source.match(/\bfetch\(/g) ?? [];
      const includeCalls = source.match(/credentials:\s*"include"/g) ?? [];
      // There must be at least one credentials:"include" per fetch call.
      // (Looser than per-call check because a shared init object would still satisfy the spec.)
      expect(includeCalls.length, "every fetch must opt into credentials").toBeGreaterThanOrEqual(
        fetchCalls.length
      );
    });

    it("uses the X-XSRF-TOKEN header on POST /auth/logout (double-submit CSRF)", () => {
      expect(source).toContain('"X-XSRF-TOKEN":');
    });

    it("readCsrfCookie handles malformed percent-encoding without throwing", () => {
      // decodeURIComponent throws URIError on malformed input; the helper
      // must catch and fall back to the raw value so signOut never crashes
      // mid-flight on a sibling-subdomain-poisoned cookie.
      expect(source).toMatch(/try\s*\{[^}]*decodeURIComponent/);
      expect(source).toMatch(/catch[^}]*\{[^}]*return raw/);
    });

    it("validates /auth/me response shape (no blind cast to User)", () => {
      // isUser type guard must run on the JSON body. A plain `as User` cast
      // would silently accept any wire format.
      expect(source).toContain("isUser(");
      expect(source).not.toMatch(/as User\b(?!\s*\|)/);
    });
  });

  describe("App.tsx (root component)", () => {
    const source = read("src/App.tsx");

    it("aborts the in-flight /auth/me fetch on unmount", () => {
      // Without AbortController + an `alive` guard, a slow /auth/me reply
      // arriving after a route change would setState on an unmounted
      // component (StrictMode double-invoke also exposes this).
      expect(source).toContain("AbortController");
      expect(source).toMatch(/controller\.abort\(\)/);
    });

    it("never accesses localStorage / sessionStorage / indexedDB", () => {
      expect(source).not.toMatch(/\blocalStorage\b/);
      expect(source).not.toMatch(/\bsessionStorage\b/);
      expect(source).not.toMatch(/\bindexedDB\b/);
    });
  });

  describe("package.json (dependency allowlist)", () => {
    it("has no in-browser OIDC library deps", () => {
      // The SPA must stay cookie-authenticated. Any in-browser OIDC client
      // would re-introduce token-in-JS storage and break the BFF contract
      // pinned in GOAL-0001 / AGENTS.md.
      // JSON.parse returns `any`; narrow it once so the assertions below
      // are type-safe and ESLint's no-unsafe-* rules pass.
      const pkg = JSON.parse(read("package.json")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const banned = [
        "oidc-client-ts",
        "oauth4webapi",
        "auth0-spa-js",
        "@auth0/auth0-spa-js",
        "oidc-react",
        "react-oidc-context",
        "keycloak-js",
        "@okta/okta-auth-js",
        "msal-browser",
        "@azure/msal-browser",
      ];
      const allDeps: Record<string, string> = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
      };
      for (const name of banned) {
        expect(allDeps[name], `package.json must not depend on ${name}`).toBeUndefined();
      }
    });
  });

  describe("vite.config.ts", () => {
    const source = read("vite.config.ts");

    it("proxies /auth and /api to the BFF", () => {
      expect(source).toContain('"/auth"');
      expect(source).toContain('"/api"');
    });

    it("keeps changeOrigin: false so the BFF sees Host: 127.0.0.1:5173", () => {
      // changeOrigin: true rewrites Host to localhost:8081, which breaks
      // OAuth redirect_uri matching (it would no longer be the SPA origin).
      expect(source).toMatch(/changeOrigin:\s*false/);
    });

    it("injects X-Forwarded-Host so the BFF computes the SPA-origin redirect_uri", () => {
      expect(source).toContain("X-Forwarded-Host");
      expect(source).toContain("X-Forwarded-Proto");
    });
  });
});
