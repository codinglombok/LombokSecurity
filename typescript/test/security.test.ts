import { test } from "node:test";
import assert from "node:assert/strict";
import { LombokSecurityError, generateCsrfToken, verifyCsrfToken, safeRedirect, tokenBucket, fixedWindow, securityHeaders, escapeHtml } from "../src/index.js";

const SECRET = "0123456789abcdef0123456789abcdef";

test("generateCsrfToken produces fresh verifiable tokens", () => {
  const a = generateCsrfToken(SECRET, "s");
  const b = generateCsrfToken(SECRET, "s");
  assert.notEqual(a, b);
  assert.ok(verifyCsrfToken(SECRET, a, "s") && verifyCsrfToken(SECRET, b, "s"));
  assert.ok(!verifyCsrfToken(SECRET, a, "t"));
});

test("errors carry a messageId", () => {
  try {
    generateCsrfToken("short");
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof LombokSecurityError);
    assert.equal(e.messageId, "lomboksecurity.error.invalid_secret");
  }
});

test("state-passing limiters are pure", () => {
  const cfg = { limit: 1, windowMs: 1000 };
  const r1 = fixedWindow(null, 0, cfg);
  assert.deepEqual(fixedWindow(r1.state, 10, cfg), fixedWindow(r1.state, 10, cfg));
  const b = tokenBucket(null, 0, { capacity: 1, refillTokens: 1, refillIntervalMs: 100 });
  assert.equal(b.state.tokens, 0);
});

test("headers never contain line breaks; escaped HTML never contains raw markup characters", () => {
  for (const [, v] of securityHeaders()) assert.ok(!/[\r\n]/.test(v));
  assert.ok(!/[<>"'&](?!(amp|lt|gt|quot|#39);)/.test(escapeHtml(`<x a="'&'">`)));
});

// Pseudo-fuzz: safeRedirect returns either the fallback, a local path that does not start with
// "//" and has no backslash or control/space characters, or an absolute URL on an allowed host.
test("fuzz: safeRedirect never returns an open redirect", () => {
  let seed = 9;
  const rnd = (): number => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
  const parts = ["/", "//", "\\", "http:", "https:", "HTTPS://", "example.com", "evil.net", "@", ":", "80", "?", "#", ".", "%2F", "\t", " ", "\u3002", "[", "]", "::1", "a"];
  for (let i = 0; i < 20000; i++) {
    const t = Array.from({ length: 1 + Math.floor(rnd() * 6) }, () => parts[Math.floor(rnd() * parts.length)]).join("");
    const r = safeRedirect(t, { allowedHosts: ["example.com"], fallback: "/home" });
    if (r === "/home") continue;
    assert.equal(r, t);
    if (r.startsWith("/")) {
      assert.ok(!r.startsWith("//") && !/[\\\u0000-\u0020\u007f]/.test(r), r);
    } else {
      const m = /^https?:\/\/([^/?#]*)/i.exec(r);
      assert.ok(m, r);
      assert.equal(m![1]!.split(":")[0]!.toLowerCase(), "example.com", r);
    }
  }
});
