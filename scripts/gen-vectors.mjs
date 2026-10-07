// Generates vectors/lomboksecurity-vectors-v1.json.
// Group "golden": expectations are WRITTEN BY HAND or copied from the cited standard (FIPS 180-4
// examples, RFC 4231); hash and HMAC expectations are additionally re-computed with node:crypto
// (an independent implementation). Every golden case is checked against the TypeScript port at
// generation time; a disagreement aborts generation.
// Group "generated-regression": seeded random inputs whose expectations come from the TypeScript
// port (hashes cross-checked with node:crypto) and are confirmed by the independent Rust port.
import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import * as lib from "../typescript/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function run(fn, args) {
  try {
    return { result: JSON.parse(JSON.stringify(lib.call(fn, args))) };
  } catch (err) {
    if (!(err instanceof lib.LombokSecurityError)) throw err;
    return { error: err.code };
  }
}
const bytes = (v) => (typeof v === "string" ? Buffer.from(v, "utf8") : Buffer.from(v.hex, "hex"));

const golden = [];
function g(name, fn, args, expect) {
  const got = run(fn, args);
  if (!isDeepStrictEqual(got, expect)) {
    throw new Error(`golden mismatch in "${name}"\n  expected ${JSON.stringify(expect)}\n  got      ${JSON.stringify(got)}`);
  }
  if ("result" in expect && fn === "sha256Hex" && expect.result !== createHash("sha256").update(bytes(args[0])).digest("hex")) throw new Error(`node:crypto disagrees: ${name}`);
  if ("result" in expect && fn === "hmacSha256Hex" && expect.result !== createHmac("sha256", bytes(args[0])).update(bytes(args[1])).digest("hex")) throw new Error(`node:crypto disagrees: ${name}`);
  golden.push({ name, fn, args, expect });
}
const ok = (result) => ({ result });
const err = (error) => ({ error });
const hex = (h) => ({ hex: h });

// ---------------------------------------------------------------- SHA-256 (FIPS 180-4 examples)
g("sha256 empty", "sha256Hex", [""], ok("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
g("sha256 abc", "sha256Hex", ["abc"], ok("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
g("sha256 448-bit message", "sha256Hex", ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"], ok("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
g("sha256 896-bit message", "sha256Hex", ["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"], ok("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
g("sha256 utf-8 input", "sha256Hex", ["caf\u00e9"], ok(createHash("sha256").update("caf\u00e9").digest("hex")));
g("sha256 bytes input", "sha256Hex", [hex("00ff")], ok(createHash("sha256").update(Buffer.from([0, 255])).digest("hex")));
for (const n of [55, 56, 63, 64, 65, 119, 120]) g(`sha256 length ${n} padding boundary`, "sha256Hex", ["a".repeat(n)], ok(createHash("sha256").update("a".repeat(n)).digest("hex")));
g("sha256 bad hex", "sha256Hex", [hex("0")], err("invalid_input"));
g("sha256 non-string", "sha256Hex", [1], err("invalid_input"));

// ---------------------------------------------------------------- HMAC-SHA256 (RFC 4231)
g("hmac rfc4231 case 1", "hmacSha256Hex", [hex("0b".repeat(20)), "Hi There"], ok("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
g("hmac rfc4231 case 2", "hmacSha256Hex", ["Jefe", "what do ya want for nothing?"], ok("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
g("hmac rfc4231 case 3", "hmacSha256Hex", [hex("aa".repeat(20)), hex("dd".repeat(50))], ok("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
g("hmac rfc4231 case 4", "hmacSha256Hex", [hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), hex("cd".repeat(50))], ok("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
g("hmac rfc4231 case 6 long key", "hmacSha256Hex", [hex("aa".repeat(131)), "Test Using Larger Than Block-Size Key - Hash Key First"], ok("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
g("hmac rfc4231 case 7 long key and data", "hmacSha256Hex", [hex("aa".repeat(131)), "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."], ok("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
for (const n of [0, 63, 64, 65]) g(`hmac key length ${n}`, "hmacSha256Hex", ["k".repeat(n), "m"], ok(createHmac("sha256", "k".repeat(n)).update("m").digest("hex")));
g("hmac non-string key", "hmacSha256Hex", [null, "m"], err("invalid_input"));

// ---------------------------------------------------------------- timingSafeEqual
g("equal strings", "timingSafeEqual", ["abc", "abc"], ok(true));
g("different strings", "timingSafeEqual", ["abc", "abd"], ok(false));
g("different lengths", "timingSafeEqual", ["abc", "abcd"], ok(false));
g("prefix", "timingSafeEqual", ["", "a"], ok(false));
g("both empty", "timingSafeEqual", ["", ""], ok(true));
g("utf-8 vs bytes", "timingSafeEqual", ["\u00e9", hex("c3a9")], ok(true));
g("repeating pattern not equal", "timingSafeEqual", ["ab", "abab"], ok(false));

// ---------------------------------------------------------------- CSRF
const SECRET = "0123456789abcdef0123456789abcdef";
const N1 = "00112233445566778899aabbccddeeff";
const mac = (secret, nonce, ctx) => createHmac("sha256", secret).update(`csrf|${nonce}|${ctx}`).digest("hex");
const T1 = `${N1}.${mac(SECRET, N1, "")}`;
const T2 = `${N1}.${mac(SECRET, N1, "session-1")}`;
g("csrf create", "createCsrfToken", [SECRET, N1], ok(T1));
g("csrf create with context", "createCsrfToken", [SECRET, N1, "session-1"], ok(T2));
g("csrf null context equals none", "createCsrfToken", [SECRET, N1, null], ok(T1));
g("csrf verify", "verifyCsrfToken", [SECRET, T1], ok(true));
g("csrf verify with context", "verifyCsrfToken", [SECRET, T2, "session-1"], ok(true));
g("csrf wrong context", "verifyCsrfToken", [SECRET, T2, "session-2"], ok(false));
g("csrf missing context", "verifyCsrfToken", [SECRET, T2], ok(false));
g("csrf wrong secret", "verifyCsrfToken", ["fedcba9876543210fedcba9876543210", T1], ok(false));
g("csrf tampered signature", "verifyCsrfToken", [SECRET, T1.slice(0, -1) + (T1.endsWith("0") ? "1" : "0")], ok(false));
g("csrf tampered nonce", "verifyCsrfToken", [SECRET, "1" + T1.slice(1)], ok(false));
g("csrf uppercase signature rejected", "verifyCsrfToken", [SECRET, T1.toUpperCase()], ok(false));
g("csrf no dot", "verifyCsrfToken", [SECRET, N1], ok(false));
g("csrf two dots", "verifyCsrfToken", [SECRET, T1 + ".x"], ok(false));
g("csrf empty", "verifyCsrfToken", [SECRET, ""], ok(false));
g("csrf non-string token", "verifyCsrfToken", [SECRET, 5], ok(false));
g("csrf short secret on create", "createCsrfToken", ["short", N1], err("invalid_secret"));
g("csrf short secret on verify", "verifyCsrfToken", ["short", T1], err("invalid_secret"));
g("csrf secret 15 bytes rejected", "createCsrfToken", ["0123456789abcde", N1], err("invalid_secret"));
g("csrf uppercase nonce with valid mac rejected", "verifyCsrfToken", [SECRET, `${N1.toUpperCase()}.${mac(SECRET, N1.toUpperCase(), "")}`], ok(false));
g("csrf short nonce with valid mac rejected", "verifyCsrfToken", [SECRET, `abcd.${mac(SECRET, "abcd", "")}`], ok(false));
g("csrf secret 16 bytes accepted", "createCsrfToken", ["0123456789abcdef", N1], ok(`${N1}.${mac("0123456789abcdef", N1, "")}`));
g("csrf secret as bytes", "createCsrfToken", [hex("00".repeat(16)), N1], ok(`${N1}.${createHmac("sha256", Buffer.alloc(16)).update(`csrf|${N1}|`).digest("hex")}`));
g("csrf nonce uppercase rejected", "createCsrfToken", [SECRET, N1.toUpperCase()], err("invalid_nonce"));
g("csrf nonce short", "createCsrfToken", [SECRET, "00"], err("invalid_nonce"));
g("csrf nonce not string", "createCsrfToken", [SECRET, 1], err("invalid_nonce"));
g("csrf context not string", "createCsrfToken", [SECRET, N1, 1], err("invalid_input"));
g("csrf secret checked first", "createCsrfToken", ["x", "bad"], err("invalid_secret"));

// ---------------------------------------------------------------- headers
const D = [
  ["Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'"],
  ["Strict-Transport-Security", "max-age=63072000; includeSubDomains"],
  ["X-Content-Type-Options", "nosniff"],
  ["X-Frame-Options", "DENY"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ["Cross-Origin-Opener-Policy", "same-origin"],
  ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
];
const H = (name, ov, r) => g(`headers ${name}`, "securityHeaders", ov === undefined ? [] : [ov], ok(r));
H("defaults", undefined, D);
H("null overrides", null, D);
H("replace keeps position and canonical name", { "x-frame-options": "SAMEORIGIN" }, D.map(([n, v]) => [n, n === "X-Frame-Options" ? "SAMEORIGIN" : v]));
H("remove with null", { "Permissions-Policy": null, "strict-transport-security": null }, D.filter(([n]) => n !== "Permissions-Policy" && n !== "Strict-Transport-Security"));
H("append new header", { "Cross-Origin-Resource-Policy": "same-site" }, [...D, ["Cross-Origin-Resource-Policy", "same-site"]]);
H("later case variant wins", { "X-A": "1", "x-a": "2" }, [...D, ["X-A", "2"]]);
H("removing unknown header is a no-op", { "X-Unknown": null }, D);
H("tab allowed in value", { "X-A": "a\tb" }, [...D, ["X-A", "a\tb"]]);
H("empty value allowed", { "X-A": "" }, [...D, ["X-A", ""]]);
g("headers newline in value", "securityHeaders", [{ "X-A": "a\r\nSet-Cookie: x=1" }], err("invalid_header"));
g("headers LF in value", "securityHeaders", [{ "X-A": "a\nb" }], err("invalid_header"));
g("headers NUL in value", "securityHeaders", [{ "X-A": "a\u0000" }], err("invalid_header"));
g("headers space in name", "securityHeaders", [{ "X A": "1" }], err("invalid_header"));
g("headers colon in name", "securityHeaders", [{ "X:A": "1" }], err("invalid_header"));
g("headers empty name", "securityHeaders", [{ "": "1" }], err("invalid_header"));
g("headers non-string value", "securityHeaders", [{ "X-A": 1 }], err("invalid_header"));
g("headers overrides not object", "securityHeaders", [[]], err("invalid_option"));

// ---------------------------------------------------------------- CSP
const C = (name, d, r) => g(`csp ${name}`, "buildCsp", [d], ok(r));
C("basic", { "default-src": ["'self'"] }, "default-src 'self'");
C("multiple", { "default-src": ["'self'"], "img-src": ["'self'", "data:", "https://cdn.example.com"], "upgrade-insecure-requests": true }, "default-src 'self'; img-src 'self' data: https://cdn.example.com; upgrade-insecure-requests");
C("empty list is flag", { sandbox: [] }, "sandbox");
C("empty object", {}, "");
C("nonce and hash sources", { "script-src": ["'nonce-abc123'", "'sha256-AbC+/='", "'strict-dynamic'"] }, "script-src 'nonce-abc123' 'sha256-AbC+/=' 'strict-dynamic'");
g("csp semicolon injection", "buildCsp", [{ "script-src": ["'self'; script-src *"] }], err("invalid_csp"));
g("csp bare semicolon", "buildCsp", [{ "script-src": ["'self';script-src"] }], err("invalid_csp"));
g("csp comma", "buildCsp", [{ "img-src": ["a,b"] }], err("invalid_csp"));
g("csp whitespace in source", "buildCsp", [{ "img-src": ["a b"] }], err("invalid_csp"));
g("csp newline in source", "buildCsp", [{ "img-src": ["a\nb"] }], err("invalid_csp"));
g("csp empty source", "buildCsp", [{ "img-src": [""] }], err("invalid_csp"));
g("csp uppercase directive", "buildCsp", [{ "Default-Src": ["'self'"] }], err("invalid_csp"));
g("csp directive starting with digit", "buildCsp", [{ "1x": ["a"] }], err("invalid_csp"));
g("csp value false", "buildCsp", [{ "img-src": false }], err("invalid_csp"));
g("csp value string", "buildCsp", [{ "img-src": "'self'" }], err("invalid_csp"));
g("csp not object", "buildCsp", [["x"]], err("invalid_csp"));

// ---------------------------------------------------------------- escapeHtml
g("escape all five", "escapeHtml", [`<a href="x" title='y'>&</a>`], ok("&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;"));
g("escape no-op", "escapeHtml", ["plain text 123"], ok("plain text 123"));
g("escape existing entity escaped again", "escapeHtml", ["&amp;"], ok("&amp;amp;"));
g("escape unicode kept", "escapeHtml", ["caf\u00e9 \u{1F600}"], ok("caf\u00e9 \u{1F600}"));
g("escape empty", "escapeHtml", [""], ok(""));
g("escape non-string", "escapeHtml", [null], err("invalid_input"));

// ---------------------------------------------------------------- safeRedirect
const AH = { allowedHosts: ["example.com", "App.Example.com"] };
const R = (name, t, o, r) => g(`redirect ${name}`, "safeRedirect", o === undefined ? [t] : [t, o], ok(r));
R("local path", "/dashboard?x=1#a", undefined, "/dashboard?x=1#a");
R("root", "/", undefined, "/");
R("protocol-relative rejected", "//evil.example.net/x", undefined, "/");
R("backslash rejected", "/\\evil.example.net", undefined, "/");
R("backslash anywhere rejected", "/a\\b", undefined, "/");
R("tab trick rejected", "/\t/evil.example.net", undefined, "/");
R("leading space rejected", " /x", undefined, "/");
R("javascript scheme rejected", "javascript:alert(1)", undefined, "/");
R("data scheme rejected", "data:text/html,x", undefined, "/");
R("relative without slash rejected", "dashboard", undefined, "/");
R("empty rejected", "", undefined, "/");
R("absolute without allow-list rejected", "https://example.com/x", undefined, "/");
R("absolute allowed host", "https://example.com/x", AH, "https://example.com/x");
R("absolute allowed case-insensitive", "HTTPS://APP.example.COM/x", AH, "HTTPS://APP.example.COM/x");
R("http allowed", "http://example.com", AH, "http://example.com");
R("port allowed", "https://example.com:8443/x", AH, "https://example.com:8443/x");
R("bad port rejected", "https://example.com:84a3/x", AH, "/");
R("long port rejected", "https://example.com:123456/x", AH, "/");
R("subdomain not implied", "https://evil.example.com/x", AH, "/");
R("suffix trick rejected", "https://example.com.evil.net/x", AH, "/");
R("userinfo rejected", "https://example.com@evil.net/x", AH, "/");
R("userinfo with allowed host rejected", "https://user@example.com/x", AH, "/");
R("empty host rejected", "https:///x", AH, "/");
R("ftp rejected", "ftp://example.com/x", AH, "/");
R("query right after host", "https://example.com?next=/", AH, "https://example.com?next=/");
R("ipv6 literal allowed", "https://[::1]:8080/x", { allowedHosts: ["[::1]"] }, "https://[::1]:8080/x");
R("ipv6 followed by non-ASCII rejected", "https://[::1]\u00e9/x", { allowedHosts: ["[::1]"] }, "/");
R("ipv6 unterminated rejected", "https://[::1/x", { allowedHosts: ["[::1]"] }, "/");
R("custom fallback", "//evil", { fallback: "/home" }, "/home");
R("non-string target", 5, undefined, "/");
R("null target", null, { fallback: "/login" }, "/login");
g("redirect fallback must be local", "safeRedirect", ["/x", { fallback: "https://example.com" }], err("invalid_option"));
g("redirect fallback protocol-relative", "safeRedirect", ["/x", { fallback: "//x" }], err("invalid_option"));
g("redirect unknown option", "safeRedirect", ["/x", { hosts: [] }], err("invalid_option"));
g("redirect allowedHosts not array", "safeRedirect", ["/x", { allowedHosts: "example.com" }], err("invalid_option"));
g("redirect allowedHosts empty entry", "safeRedirect", ["/x", { allowedHosts: [""] }], err("invalid_option"));

// ---------------------------------------------------------------- checkPassword
const P = (name, pw, policy, r) => g(`password ${name}`, "checkPassword", policy === undefined ? [pw] : [pw, policy], ok(r));
P("good default", "correct horse battery staple", undefined, []);
P("too short default 12", "abcdefghijk", undefined, ["too_short"]);
P("exactly 12", "abcdefghijkl", undefined, []);
P("common password", "password", { minLength: 1 }, ["common_password"]);
P("common password case-insensitive", "PassWord123", { minLength: 1 }, ["common_password"]);
P("common and short", "qwerty", undefined, ["too_short", "common_password"]);
P("blocklist disabled", "qwerty", { minLength: 1, blocklist: false }, []);
P("extra blocklist", "lombok-rocks", { minLength: 1, extraBlocklist: ["LOMBOK-ROCKS"] }, ["common_password"]);
P("too long", "a".repeat(9), { minLength: 1, maxLength: 8 }, ["too_long"]);
P("length counts code points", "\u{1F600}".repeat(12), undefined, []);
P("length counts code points short", "\u{1F600}".repeat(11), undefined, ["too_short"]);
P("composition all missing", "                ", { requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: true }, ["missing_lowercase", "missing_uppercase", "missing_digit", "missing_symbol"]);
P("composition satisfied", "aB3!aaaaaaaa", { requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: true }, []);
P("non-ASCII letters do not count", "\u00e9\u00c9\u00e9\u00c9\u00e9\u00c9\u00e9\u00c9\u00e9\u00c9\u00e9\u00c9", { requireLowercase: true, requireUppercase: true }, ["missing_lowercase", "missing_uppercase"]);
P("space is not a symbol", "abcdefghijk l", { requireSymbol: true }, ["missing_symbol"]);
P("tilde is a symbol", "abcdefghijk~", { requireSymbol: true }, []);
P("repeat limit", "aaab-long-enough", { maxRepeat: 2 }, ["repeated_characters"]);
P("repeat at limit", "aab-long-enough", { maxRepeat: 2 }, []);
P("repeat disabled by default", "aaaaaaaaaaaaaaaa", undefined, []);
P("user input contained", "my-ana.wijaya-pass", { userInputs: ["Ana.Wijaya", "ana@example.com"] }, ["contains_user_input"]);
P("short user input ignored", "correct horse battery", { userInputs: ["co"] }, []);
P("all rules order", "Ana", { minLength: 8, requireDigit: true, userInputs: ["ana"] }, ["too_short", "missing_digit", "contains_user_input"]);
g("password not string", "checkPassword", [null], err("invalid_input"));
g("password policy checked before password", "checkPassword", [null, { minLength: 0 }], err("invalid_option"));
g("password unknown policy key", "checkPassword", ["x", { min: 1 }], err("invalid_option"));
g("password min greater than max", "checkPassword", ["x", { minLength: 5, maxLength: 4 }], err("invalid_option"));
g("password bool option type", "checkPassword", ["x", { requireDigit: "yes" }], err("invalid_option"));
g("password list option type", "checkPassword", ["x", { userInputs: "ana" }], err("invalid_option"));
g("password negative maxRepeat", "checkPassword", ["x", { maxRepeat: -1 }], err("invalid_option"));

// ---------------------------------------------------------------- rate limiting
const A = (allowed, remaining, retryAfter) => ({ allowed, remaining, retryAfter });
const RL = (name, kind, cfg, times, r) => g(`ratelimit ${name}`, "simulateRateLimit", [kind, cfg, times], ok(r));
RL("fixed window basic", "fixedWindow", { limit: 2, windowMs: 1000 }, [0, 10, 20, 999, 1000], [A(true, 1, 0), A(true, 0, 0), A(false, 0, 980), A(false, 0, 1), A(true, 1, 0)]);
RL("fixed window aligned to multiples", "fixedWindow", { limit: 1, windowMs: 1000 }, [1500, 1999, 2000], [A(true, 0, 0), A(false, 0, 1), A(true, 0, 0)]);
RL("fixed window skips windows", "fixedWindow", { limit: 1, windowMs: 10 }, [5, 95, 96], [A(true, 0, 0), A(true, 0, 0), A(false, 0, 4)]);
RL("fixed window limit 1 burst", "fixedWindow", { limit: 1, windowMs: 60000 }, [0, 0, 0], [A(true, 0, 0), A(false, 0, 60000), A(false, 0, 60000)]);
RL("token bucket basic", "tokenBucket", { capacity: 2, refillTokens: 1, refillIntervalMs: 1000 }, [0, 0, 0, 500, 1000, 2500], [A(true, 1, 0), A(true, 0, 0), A(false, 0, 1000), A(false, 0, 500), A(true, 0, 0), A(true, 0, 0)]);
RL("token bucket refill capped", "tokenBucket", { capacity: 3, refillTokens: 2, refillIntervalMs: 100 }, [0, 0, 0, 10000, 10000, 10000, 10000], [A(true, 2, 0), A(true, 1, 0), A(true, 0, 0), A(true, 2, 0), A(true, 1, 0), A(true, 0, 0), A(false, 0, 100)]);
RL("token bucket cost", "tokenBucket", { capacity: 5, refillTokens: 1, refillIntervalMs: 10, cost: 3 }, [0, 0, 15, 20], [A(true, 2, 0), A(false, 2, 10), A(true, 0, 0), A(false, 1, 20)]);
RL("token bucket clock backwards", "tokenBucket", { capacity: 1, refillTokens: 1, refillIntervalMs: 100 }, [1000, 900, 1100], [A(true, 0, 0), A(false, 0, 100), A(true, 0, 0)]);
RL("empty sequence", "fixedWindow", { limit: 1, windowMs: 1 }, [], []);
g("ratelimit unknown kind", "simulateRateLimit", ["slidingLog", { limit: 1, windowMs: 1 }, [0]], err("invalid_option"));
g("ratelimit zero limit", "simulateRateLimit", ["fixedWindow", { limit: 0, windowMs: 1 }, [0]], err("invalid_option"));
g("ratelimit fractional window", "simulateRateLimit", ["fixedWindow", { limit: 1, windowMs: 1.5 }, [0]], err("invalid_option"));
g("ratelimit negative time", "simulateRateLimit", ["fixedWindow", { limit: 1, windowMs: 1 }, [-1]], err("invalid_option"));
g("ratelimit cost over capacity", "simulateRateLimit", ["tokenBucket", { capacity: 1, refillTokens: 1, refillIntervalMs: 1, cost: 2 }, [0]], err("invalid_option"));
g("ratelimit times not array", "simulateRateLimit", ["fixedWindow", { limit: 1, windowMs: 1 }, 0], err("invalid_option"));
g("ratelimit config not object", "simulateRateLimit", ["tokenBucket", null, [0]], err("invalid_option"));
g("unknown function", "nope", [], err("invalid_option"));

// ---------------------------------------------------------------- generated regression
let seed = 0x5ec0de11;
const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const randHex = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 256).toString(16).padStart(2, "0")).join("");
const generated = [];
const push = (name, fn, args) => {
  const expect = run(fn, args);
  if ("result" in expect && fn === "sha256Hex" && expect.result !== createHash("sha256").update(bytes(args[0])).digest("hex")) throw new Error("sha mismatch");
  if ("result" in expect && fn === "hmacSha256Hex" && expect.result !== createHmac("sha256", bytes(args[0])).update(bytes(args[1])).digest("hex")) throw new Error("hmac mismatch");
  generated.push({ name: `generated ${String(generated.length + 1).padStart(3, "0")} ${name}`, fn, args, expect });
};
for (let i = 0; i < 30; i++) push("sha256", "sha256Hex", [hex(randHex(Math.floor(rnd() * 200)))]);
for (let i = 0; i < 30; i++) push("hmac", "hmacSha256Hex", [hex(randHex(Math.floor(rnd() * 150))), hex(randHex(Math.floor(rnd() * 150)))]);
for (let i = 0; i < 20; i++) {
  const nonce = randHex(16);
  const ctx = pick([undefined, "s1", "", "caf\u00e9"]);
  const tok = run("createCsrfToken", ctx === undefined ? [SECRET, nonce] : [SECRET, nonce, ctx]).result;
  push("csrf verify", "verifyCsrfToken", [SECRET, rnd() < 0.5 ? tok : tok.slice(0, 40) + randHex(1) + tok.slice(42), pick([undefined, "s1", "", "caf\u00e9"]) ?? null]);
}
const pathParts = ["", "/", "//", "\\", "http://", "https://", "example.com", "evil.net", "@", ":443", "?q=/", "#x", "a", "%2f", " ", "\t", "[::1]"];
for (let i = 0; i < 40; i++) {
  const t = Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => pick(pathParts)).join("");
  push("redirect", "safeRedirect", [t, { allowedHosts: ["example.com", "[::1]"] }]);
}
for (let i = 0; i < 20; i++) {
  const pw = Array.from({ length: Math.floor(rnd() * 16) }, () => pick(["a", "A", "1", "!", " ", "a", "\u00e9", "ana", "x"])).join("");
  push("password", "checkPassword", [pw, { minLength: 6, maxLength: 14, requireDigit: rnd() < 0.5, requireSymbol: rnd() < 0.5, maxRepeat: pick([0, 2]), userInputs: ["ana"] }]);
}
for (let i = 0; i < 20; i++) {
  let t = 0;
  const times = Array.from({ length: 12 }, () => (t += Math.floor(rnd() * 400)));
  const kind = i % 2 ? "fixedWindow" : "tokenBucket";
  const cfg = kind === "fixedWindow" ? { limit: 1 + Math.floor(rnd() * 3), windowMs: pick([100, 500, 1000]) } : { capacity: 1 + Math.floor(rnd() * 4), refillTokens: 1 + Math.floor(rnd() * 2), refillIntervalMs: pick([100, 300, 1000]) };
  push("ratelimit", "simulateRateLimit", [kind, cfg, times]);
}

const doc = {
  format: "lomboksecurity-vectors-v1",
  specVersion: "0.1.0",
  note: "Normative cross-language vectors. Each case calls `fn` with `args` ({\"hex\": ...} denotes bytes); `expect` is {result} or {error: code}.",
  groups: [
    { name: "golden", cases: golden },
    { name: "generated-regression", cases: generated },
  ],
};
// ASCII-only file: non-ASCII characters are written as JSON \u escapes (UTF-16 code units).
const ascii = JSON.stringify(doc, null, 1).replace(/[\u0080-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
writeFileSync(join(root, "vectors", "lomboksecurity-vectors-v1.json"), ascii + "\n");
const sha = createHash("sha256").update(readFileSync(join(root, "vectors", "lomboksecurity-vectors-v1.json"))).digest("hex");
console.log(`golden=${golden.length} generated=${generated.length} total=${golden.length + generated.length} sha256=${sha}`);
