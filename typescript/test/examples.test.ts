import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildCsp, checkPassword, safeRedirect, securityHeaders, simulateRateLimit } from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (p: string): string => readFileSync(join(root, p), "utf8");

test("README quick-start comments match the library", () => {
  assert.equal(safeRedirect("//evil.example.net/x"), "/");
  assert.equal(safeRedirect("https://app.example.com/home", { allowedHosts: ["app.example.com"] }), "https://app.example.com/home");
  assert.deepEqual(checkPassword("password"), ["too_short", "common_password"]);
  assert.ok(read("README.md").includes('checkPassword("password");                                // ["too_short", "common_password"]'));
  assert.equal(securityHeaders({ "X-Frame-Options": "SAMEORIGIN" }).find(([n]) => n === "X-Frame-Options")![1], "SAMEORIGIN");
});

test("guide recipes behave as documented", () => {
  const g = read("docs/guide_how_to_use_LombokSecurity_v0.1.0.md");
  const csp = buildCsp({ "default-src": ["'self'"], "img-src": ["'self'", "data:"], "upgrade-insecure-requests": true });
  assert.equal(csp, "default-src 'self'; img-src 'self' data:; upgrade-insecure-requests");
  assert.ok(g.includes(csp));
  const rl = simulateRateLimit("fixedWindow", { limit: 2, windowMs: 60000 }, [0, 1000, 2000]);
  assert.deepEqual(rl.map((r) => r.allowed), [true, true, false]);
  assert.equal(rl[2]!.retryAfter, 58000);
  assert.ok(g.includes("58000"));
});
