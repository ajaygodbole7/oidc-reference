// Meta-test: writes a temp file that violates the storage ban and asserts
// ESLint catches it. Without this, someone could silently delete the
// no-restricted-syntax rule from eslint.config.js and the no-token-storage
// invariant would only be caught at e2e time (minutes), not at lint
// (seconds).
//
// Pattern borrowed from ~/react-template/tests/unit/eslint-boundary.test.js.

import { execFileSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

interface EslintMessage {
  ruleId: string | null;
  message: string;
}

interface EslintResult {
  messages: EslintMessage[];
}

const TEMP_FILE = path.resolve("src/_eslint-boundary-temp.ts");

function lint(filePath: string): EslintMessage[] {
  let stdout = "[]";
  try {
    stdout = execFileSync("npx", ["eslint", "--format", "json", filePath], {
      stdio: ["ignore", "pipe", "pipe"]
    }).toString();
  } catch (e) {
    const buf = (e as { stdout?: Buffer }).stdout;
    if (buf) stdout = buf.toString();
  }
  const results = JSON.parse(stdout) as EslintResult[];
  return results[0]?.messages ?? [];
}

describe("ESLint storage-ban boundary", () => {
  afterEach(() => {
    try {
      unlinkSync(TEMP_FILE);
    } catch {
      // ignore
    }
  });

  it("blocks localStorage.setItem in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { localStorage.setItem('t', 'x'); }\n");
    const messages = lint(TEMP_FILE);
    const restricted = messages.find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "no-restricted-syntax must flag localStorage.setItem").toBeDefined();
    expect(restricted?.message).toMatch(/web storage/i);
  });

  it("blocks sessionStorage.setItem in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { sessionStorage.setItem('t', 'x'); }\n");
    const messages = lint(TEMP_FILE);
    const restricted = messages.find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "no-restricted-syntax must flag sessionStorage.setItem").toBeDefined();
  });

  it("blocks indexedDB reference in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export const db = indexedDB;\n");
    const messages = lint(TEMP_FILE);
    const restricted = messages.find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "no-restricted-syntax must flag indexedDB").toBeDefined();
  });

  it("blocks direct document.cookie writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { document.cookie = 'access_token=x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag document.cookie assignment").toBeDefined();
    expect(restricted?.message).toMatch(/document\.cookie/i);
  });

  it("blocks bracket-access document.cookie writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { document['cookie'] = 'access_token=x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag document['cookie'] assignment").toBeDefined();
  });

  it("blocks qualified document.cookie writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { window.document.cookie = 'access_token=x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag window.document.cookie assignment").toBeDefined();
  });

  it("blocks fully bracket-qualified document.cookie writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { globalThis['document']['cookie'] = 'access_token=x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag globalThis['document']['cookie'] assignment").toBeDefined();
  });

  it("blocks window-qualified storage writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { window.localStorage.setItem('t', 'x'); }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag window.localStorage.setItem").toBeDefined();
  });

  it("blocks bracket-access storage writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { localStorage['setItem']('t', 'x'); }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag localStorage['setItem']").toBeDefined();
  });

  it("blocks direct assignment into storage in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { localStorage['token'] = 'x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag localStorage assignment").toBeDefined();
  });

  it("blocks bracket-qualified global storage writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { window['localStorage'].setItem('t', 'x'); }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag window['localStorage'].setItem").toBeDefined();
  });

  it("blocks fully bracket-qualified global storage writes in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { globalThis['sessionStorage']['setItem']('t', 'x'); }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag globalThis['sessionStorage']['setItem']").toBeDefined();
  });

  it("blocks bracket-qualified global storage assignment in src/", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export function leak() { window['localStorage']['token'] = 'x'; }\n");
    const restricted = lint(TEMP_FILE).find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "must flag window['localStorage']['token'] = ...").toBeDefined();
  });

  it("allows storage reads (no setItem) — debug tools need them", { timeout: 30000 }, () => {
    writeFileSync(TEMP_FILE, "export const n = localStorage.length;\n");
    const messages = lint(TEMP_FILE);
    const restricted = messages.find((m) => m.ruleId === "no-restricted-syntax");
    expect(restricted, "reading localStorage.length must not be banned").toBeUndefined();
  });
});
