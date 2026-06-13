import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Node 24+ ships a NATIVE global `localStorage`/`sessionStorage` (Web Storage
// API) that is unavailable unless the process is started with
// `--localstorage-file`, and it SHADOWS jsdom's `window.localStorage`. Under the
// jsdom test env on a newer Node the bare `localStorage` global is therefore
// `undefined`, and the token-isolation assertions (`localStorage.length === 0`)
// throw `Cannot read properties of undefined`. Bind the bare globals to jsdom's
// real Storage (memory fallback if jsdom didn't provide one) so the suite runs
// on WHATEVER Node is installed — not only the .nvmrc-pinned version.
class MemoryStorage implements Storage {
  private readonly map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
}

function ensureStorage(name: "localStorage" | "sessionStorage"): void {
  // If the current global is already a usable Storage (jsdom on Node <24), keep it.
  let current: Storage | undefined;
  try {
    current = (globalThis as unknown as Record<string, Storage | undefined>)[name];
  } catch {
    current = undefined; // Node's native getter can throw when unconfigured.
  }
  if (current && typeof current.getItem === "function" && typeof current.length === "number") {
    return;
  }
  const win = (globalThis as unknown as { window?: Record<string, Storage | undefined> }).window;
  const jsdomStorage = win?.[name];
  const replacement: Storage =
    jsdomStorage && typeof jsdomStorage.getItem === "function" ? jsdomStorage : new MemoryStorage();
  Object.defineProperty(globalThis, name, {
    value: replacement,
    configurable: true,
    writable: true
  });
}

ensureStorage("localStorage");
ensureStorage("sessionStorage");

afterEach(() => {
  cleanup();
});
