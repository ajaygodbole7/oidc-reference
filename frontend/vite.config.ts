/// <reference types="vitest" />

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
import type { ProxyOptions } from "vite";

// The browser is at http://127.0.0.1:5173. In the Frame B split-BFF
// architecture there are TWO upstreams instead of one:
//   - /auth/* → Auth Service (http://127.0.0.1:8081)
//   - /api/** → APISIX        (http://127.0.0.1:9080)
//
// In a full `docker compose up` run, APISIX is the actual ingress and
// path-routes both /auth/* and /api/** itself. The Vite dev proxy is the
// dev-loop equivalent of that ingress: it splits the two prefixes here
// so that the inner loop (frontend dev) can talk to Auth Service running
// via `./mvnw spring-boot:run` and to APISIX (with the rest of the
// backend behind it) running in Compose, without the SPA having to know
// either is separate.
//
// Both proxies use the same forwarded-header treatment as before:
//   - changeOrigin is false so upstreams receive Host: 127.0.0.1:5173
//   - X-Forwarded-* tell Spring's ForwardedHeaderFilter
//     (server.forward-headers-strategy=framework) to compute baseUrl as
//     the SPA origin, so the OAuth redirect_uri matches the URI
//     registered in Keycloak (http://127.0.0.1:5173/auth/callback/idp).
//   - The OAuth callback lands at 127.0.0.1:5173 (Vite), is proxied to
//     Auth Service, and the Set-Cookie response flows back through Vite.
//     The browser binds the cookie to origin 5173, so subsequent
//     /api/** and /auth/me requests carry it.
const authTarget = process.env.VITE_AUTH_TARGET ?? "http://127.0.0.1:8081";
const apiTarget = process.env.VITE_API_TARGET ?? "http://127.0.0.1:9080";

const forwardedHeaderProxy = (target: string): ProxyOptions => ({
  target,
  changeOrigin: false,
  configure: (proxy) => {
    proxy.on("proxyReq", (proxyReq, req) => {
      const host = req.headers.host ?? "127.0.0.1:5173";
      proxyReq.setHeader("X-Forwarded-Host", host);
      proxyReq.setHeader("X-Forwarded-Proto", "http");
      proxyReq.setHeader("X-Forwarded-Port", "5173");
    });
  }
});

const authProxy: ProxyOptions = forwardedHeaderProxy(authTarget);
const apiProxy: ProxyOptions = forwardedHeaderProxy(apiTarget);

// We intentionally do NOT set Content-Security-Policy from the dev server.
// Vite's HMR client needs runtime code generation that any sensible CSP
// would block, so a "dev CSP" is either toothless (allow everything) or
// breaks the inner loop. Production CSP is owned by the Auth Service /
// APISIX response headers and the production web server — that's where
// it belongs and where it can be nonce-based without HMR getting in the
// way.
//
// Referrer-Policy and X-Content-Type-Options are uncontroversial in dev
// and useful for parity with production behavior.
const devSecurityHeaders = {
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff"
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    headers: devSecurityHeaders,
    proxy: {
      "/auth": authProxy,
      "/api": apiProxy
    }
  },
  build: {
    target: "es2022",
    sourcemap: true,
    reportCompressedSize: false
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test-setup.ts"]
  }
});
