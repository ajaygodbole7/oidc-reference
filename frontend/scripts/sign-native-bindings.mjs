// macOS-only: ad-hoc sign the rolldown prebuilt native binding after install.
//
// vite 8 / vitest 4 load a prebuilt `@rolldown/binding-darwin-*/*.node` that npm
// publishes UNSIGNED. macOS (12+) refuses to dlopen an unsigned dylib
// ("code object is not signed at all"), which breaks `vitest`, `vite build`, and
// the Vite dev server the e2e suite serves the SPA from. An ad-hoc signature
// (`codesign --sign -`) satisfies the loader without changing the bits' behavior.
//
// Runs as a `postinstall` hook so the fix survives every `npm install` / `npm ci`
// rather than needing a manual step. No-op on non-macOS (Linux CI and production
// load unsigned dylibs fine) and harmless on an already-signed binary.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

if (process.platform !== "darwin") {
  process.exit(0);
}

const rolldownDir = join(process.cwd(), "node_modules", "@rolldown");
if (!existsSync(rolldownDir)) {
  process.exit(0);
}

let signed = 0;
for (const entry of readdirSync(rolldownDir)) {
  if (!entry.startsWith("binding-darwin")) {
    continue;
  }
  const bindingDir = join(rolldownDir, entry);
  for (const file of readdirSync(bindingDir)) {
    if (!file.endsWith(".node")) {
      continue;
    }
    try {
      execFileSync("codesign", ["--force", "--sign", "-", join(bindingDir, file)], {
        stdio: "ignore",
      });
      signed += 1;
    } catch {
      // codesign missing or failed — leave it; the loader's own error is clear.
    }
  }
}

if (signed > 0) {
  console.log(`sign-native-bindings: ad-hoc signed ${signed} rolldown binding(s) for macOS`);
}
