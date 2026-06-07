// Fails CI if the built SPA exceeds its budget, or if first-party debug
// markers leak into the production bundle. The SPA is the canonical example
// of a token-free browser surface; a regression that adds a heavy OAuth/OIDC
// client library would jump the bundle and surface here.
//
// Budgets are tight on purpose — the SPA is ~90 LOC of TS + React. Bump
// these only when adding a legitimate feature, and explain why in the PR.

import { readdirSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";

const distDir = path.resolve("dist/assets");
const budget = {
  main: 100 * 1024, // 100 KB gzipped for the main entry
  total: 200 * 1024 // 200 KB gzipped across all assets
};

// Any of these strings showing up in the production bundle means a first-party
// debug log slipped through. Add real markers as the codebase grows.
const forbiddenBundleMarkers = [
  "console.debug(",
  "TODO:",
  "FIXME:"
];

let files;
try {
  files = readdirSync(distDir).filter((f) => f.endsWith(".js") || f.endsWith(".css"));
} catch {
  console.error('FAIL: dist/assets not found. Run "npm run build" first.');
  process.exit(1);
}

let totalGzip = 0;
let mainChunkSize = 0;
const forbiddenMatches = [];

console.log("Bundle size report:");
console.log("---");

for (const file of files) {
  const content = readFileSync(path.join(distDir, file));
  const gzipped = gzipSync(content);
  const sizeKB = (gzipped.length / 1024).toFixed(1);
  console.log(`  ${file}: ${sizeKB} KB gzipped`);
  totalGzip += gzipped.length;

  if (file.startsWith("index") && file.endsWith(".js")) {
    mainChunkSize = gzipped.length;
  }

  if (file.endsWith(".js")) {
    const text = content.toString("utf8");
    for (const marker of forbiddenBundleMarkers) {
      if (text.includes(marker)) {
        forbiddenMatches.push(`${file}: ${marker}`);
      }
    }
  }
}

console.log(`\nTotal: ${(totalGzip / 1024).toFixed(1)} KB gzipped`);

let failed = false;

if (mainChunkSize > budget.main) {
  console.error(
    `FAIL: Main chunk ${(mainChunkSize / 1024).toFixed(1)}KB exceeds ${budget.main / 1024}KB budget`
  );
  failed = true;
}

if (totalGzip > budget.total) {
  console.error(
    `FAIL: Total ${(totalGzip / 1024).toFixed(1)}KB exceeds ${budget.total / 1024}KB budget`
  );
  failed = true;
}

if (forbiddenMatches.length) {
  console.error("FAIL: First-party debug markers found in production bundle:");
  for (const match of forbiddenMatches) {
    console.error(`  ${match}`);
  }
  failed = true;
}

if (failed) {
  process.exit(1);
}

console.log("PASS: Within budget");
