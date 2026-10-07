// LombokSecurity core (TypeScript port). Normative behaviour: docs/SPEC_LombokSecurity_v0.1.0.md.
// Pure functions: randomness and time are supplied by the caller (except generateCsrfToken).
import { constantTimeEqual, fromHex, hmacSha256, sha256, toHex, utf8, type Bytes } from "./crypto.js";

export type ErrorCode = "invalid_secret" | "invalid_nonce" | "invalid_header" | "invalid_csp" | "invalid_option" | "invalid_input";

export class LombokSecurityError extends Error {
  readonly code: ErrorCode;
  readonly messageId: string;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "LombokSecurityError";
    this.code = code;
    this.messageId = `lomboksecurity.error.${code}`;
  }
}

const fail = (code: ErrorCode, message: string): never => {
  throw new LombokSecurityError(code, message);
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
const MAX_SAFE = 9007199254740991;

function bytesOf(v: unknown, what: string): Bytes {
  if (typeof v === "string") return utf8(v);
  if (v instanceof Uint8Array) return v;
  return fail("invalid_input", `${what} must be a string or bytes`);
}

// ---------------------------------------------------------------- hashing

/** Lowercase hex SHA-256 of a string (UTF-8) or bytes. */
export function sha256Hex(data: string | Bytes): string {
  return toHex(sha256(bytesOf(data, "data")));
}

/** Lowercase hex HMAC-SHA256. */
export function hmacSha256Hex(key: string | Bytes, data: string | Bytes): string {
  return toHex(hmacSha256(bytesOf(key, "key"), bytesOf(data, "data")));
}

/** Equality of two strings (UTF-8) or byte arrays in time that depends only on the lengths. */
export function timingSafeEqual(a: string | Bytes, b: string | Bytes): boolean {
  return constantTimeEqual(bytesOf(a, "a"), bytesOf(b, "b"));
}

// ---------------------------------------------------------------- CSRF

export const MIN_SECRET_BYTES = 16;
const NONCE = /^[0-9a-f]{32}$/;
const SIG = /^[0-9a-f]{64}$/;

function secretBytes(secret: unknown): Bytes {
  const b = bytesOf(secret, "secret");
  if (b.length < MIN_SECRET_BYTES) return fail("invalid_secret", "secret must be at least 16 bytes");
  return b;
}

function contextOf(context: unknown): string {
  if (context === undefined || context === null) return "";
  if (typeof context !== "string") return fail("invalid_input", "context must be a string");
  return context;
}

const csrfMac = (secret: Bytes, nonce: string, context: string): string => toHex(hmacSha256(secret, utf8(`csrf|${nonce}|${context}`)));

/** Token `nonce.signature` for a caller-supplied 16-byte nonce (32 lowercase hex digits). */
export function createCsrfToken(secret: string | Bytes, nonceHex: string, context?: string | null): string {
  const s = secretBytes(secret);
  if (typeof nonceHex !== "string" || !NONCE.test(nonceHex)) return fail("invalid_nonce", "nonce must be 32 lowercase hex digits");
  const c = contextOf(context);
  return `${nonceHex}.${csrfMac(s, nonceHex, c)}`;
}

/** True only for a well-formed token signed with `secret` for the same `context`. */
export function verifyCsrfToken(secret: string | Bytes, token: unknown, context?: string | null): boolean {
  const s = secretBytes(secret);
  const c = contextOf(context);
  if (typeof token !== "string") return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const nonce = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!NONCE.test(nonce) || !SIG.test(sig)) return false;
  return constantTimeEqual(utf8(csrfMac(s, nonce, c)), utf8(sig));
}

/** Convenience: token with a fresh nonce from `crypto.getRandomValues`. */
export function generateCsrfToken(secret: string | Bytes, context?: string | null): string {
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (!c || typeof c.getRandomValues !== "function") return fail("invalid_option", "no secure random source (crypto.getRandomValues) is available");
  return createCsrfToken(secret, toHex(c.getRandomValues(new Uint8Array(16))), context);
}

// ---------------------------------------------------------------- headers and CSP

export const DEFAULT_HEADERS: readonly (readonly [string, string])[] = [
  ["Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'"],
  ["Strict-Transport-Security", "max-age=63072000; includeSubDomains"],
  ["X-Content-Type-Options", "nosniff"],
  ["X-Frame-Options", "DENY"],
  ["Referrer-Policy", "strict-origin-when-cross-origin"],
  ["Cross-Origin-Opener-Policy", "same-origin"],
  ["Permissions-Policy", "camera=(), microphone=(), geolocation=()"],
];

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
// eslint-disable-next-line no-control-regex
const BAD_VALUE = /[\u0000-\u0008\u000a-\u001f\u007f]/;

/**
 * Recommended response headers as ordered `[name, value]` pairs. `overrides` maps header names to
 * a value (replace or add) or `null` (remove). Names match defaults case-insensitively.
 */
export function securityHeaders(overrides?: Record<string, string | null> | null): [string, string][] {
  const out: [string, string | null][] = DEFAULT_HEADERS.map(([n, v]) => [n, v]);
  if (overrides !== undefined && overrides !== null) {
    if (!isObject(overrides)) return fail("invalid_option", "overrides must be an object");
    for (const name of Object.keys(overrides)) {
      if (!TOKEN.test(name)) fail("invalid_header", "header name is not an RFC 9110 token");
      const v = overrides[name];
      if (v !== null && (typeof v !== "string" || BAD_VALUE.test(v))) fail("invalid_header", "header value must be a string without CR, LF or control characters");
      const i = out.findIndex(([n]) => asciiLower(n) === asciiLower(name));
      if (i >= 0) out[i] = [out[i]![0], v as string | null];
      else out.push([name, v as string | null]);
    }
  }
  return out.filter((p): p is [string, string] => p[1] !== null);
}

const DIRECTIVE = /^[a-z][a-z0-9-]*$/;
// eslint-disable-next-line no-control-regex
const BAD_SOURCE = /[\u0000-\u0020\u007f;,]/;

/** Serialize CSP directives: `{ "img-src": ["'self'", "data:"], "upgrade-insecure-requests": true }`. */
export function buildCsp(directives: Record<string, string[] | true>): string {
  if (!isObject(directives)) return fail("invalid_csp", "directives must be an object");
  const parts: string[] = [];
  for (const name of Object.keys(directives)) {
    if (!DIRECTIVE.test(name)) fail("invalid_csp", "invalid directive name");
    const v = directives[name];
    if (v === true) {
      parts.push(name);
      continue;
    }
    if (!Array.isArray(v)) return fail("invalid_csp", "directive value must be an array of sources or true");
    for (const s of v) if (typeof s !== "string" || s === "" || BAD_SOURCE.test(s)) fail("invalid_csp", "invalid source expression");
    parts.push(v.length === 0 ? name : `${name} ${v.join(" ")}`);
  }
  return parts.join("; ");
}

// ---------------------------------------------------------------- output encoding and redirects

/** Escape `& < > " '` for HTML text and quoted attribute values. */
export function escapeHtml(text: string): string {
  if (typeof text !== "string") return fail("invalid_input", "text must be a string");
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

export interface RedirectOptions {
  allowedHosts?: string[];
  fallback?: string;
}

// eslint-disable-next-line no-control-regex
const UNSAFE_CHAR = /[\u0000-\u0020\u007f\\]/;
const isLocalPath = (s: string): boolean => s.startsWith("/") && !s.startsWith("//") && !UNSAFE_CHAR.test(s);

/**
 * `target` when it is a local path (`/x`, not `//x`) or an absolute http(s) URL whose host is in
 * `allowedHosts`; otherwise `fallback` (default `/`). Prevents open redirects.
 */
export function safeRedirect(target: unknown, options?: RedirectOptions | null): string {
  let allowed: string[] = [];
  let fallback = "/";
  if (options !== undefined && options !== null) {
    if (!isObject(options)) return fail("invalid_option", "options must be an object");
    for (const k of Object.keys(options)) if (k !== "allowedHosts" && k !== "fallback") fail("invalid_option", `unknown option: ${k}`);
    const a = options["allowedHosts"];
    if (a !== undefined) {
      if (!Array.isArray(a) || a.some((h) => typeof h !== "string" || h === "")) return fail("invalid_option", "allowedHosts must be an array of non-empty strings");
      allowed = (a as string[]).map(asciiLower);
    }
    const f = options["fallback"];
    if (f !== undefined) {
      if (typeof f !== "string" || !isLocalPath(f)) return fail("invalid_option", "fallback must be a local path");
      fallback = f;
    }
  }
  if (typeof target !== "string" || target === "" || UNSAFE_CHAR.test(target)) return fallback;
  if (isLocalPath(target)) return target;
  const m = /^https?:\/\/([^/?#]*)/i.exec(target);
  if (m === null) return fallback;
  const authority = m[1] as string;
  if (authority === "" || authority.includes("@")) return fallback;
  let host: string;
  let rest: string;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) return fallback;
    host = authority.slice(0, end + 1);
    rest = authority.slice(end + 1);
  } else {
    const c = authority.indexOf(":");
    host = c < 0 ? authority : authority.slice(0, c);
    rest = c < 0 ? "" : authority.slice(c);
  }
  if (rest !== "" && !/^:[0-9]{1,5}$/.test(rest)) return fallback;
  if (host === "") return fallback;
  return allowed.includes(asciiLower(host)) ? target : fallback;
}

// ---------------------------------------------------------------- passwords

export const COMMON_PASSWORDS: readonly string[] = [
  "123456", "123456789", "12345678", "1234567890", "password", "password1", "password123", "qwerty", "qwerty123", "qwertyuiop",
  "abc123", "111111", "000000", "iloveyou", "admin", "admin123", "welcome", "welcome1", "letmein", "monkey",
  "dragon", "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "trustno1", "passw0rd",
  "1q2w3e4r", "zaq12wsx", "changeme", "secret", "login", "starwars", "whatever", "123123", "654321", "1qaz2wsx",
];

export interface PasswordPolicy {
  minLength?: number;
  maxLength?: number;
  requireLowercase?: boolean;
  requireUppercase?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
  /** Longest allowed run of one repeated character; 0 disables the check. */
  maxRepeat?: number;
  /** Check the built-in common-password list. */
  blocklist?: boolean;
  extraBlocklist?: string[];
  /** Strings the password must not contain (username, email, site name); entries shorter than 3 are ignored. */
  userInputs?: string[];
}

const POLICY_KEYS = ["minLength", "maxLength", "requireLowercase", "requireUppercase", "requireDigit", "requireSymbol", "maxRepeat", "blocklist", "extraBlocklist", "userInputs"];

/** Violated rules in fixed order; an empty array means the password satisfies the policy. */
export function checkPassword(password: unknown, policy?: PasswordPolicy | null): string[] {
  const p: Record<string, unknown> = {};
  if (policy !== undefined && policy !== null) {
    if (!isObject(policy)) return fail("invalid_option", "policy must be an object");
    for (const k of Object.keys(policy)) {
      if (!POLICY_KEYS.includes(k)) fail("invalid_option", `unknown policy key: ${k}`);
      p[k] = policy[k];
    }
  }
  const int = (k: string, d: number, min: number): number => {
    if (!has(p, k) || p[k] === undefined) return d;
    const v = p[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > MAX_SAFE) return fail("invalid_option", `${k} must be an integer >= ${min}`);
    return v;
  };
  const bool = (k: string, d: boolean): boolean => {
    if (!has(p, k) || p[k] === undefined) return d;
    if (typeof p[k] !== "boolean") return fail("invalid_option", `${k} must be a boolean`);
    return p[k] as boolean;
  };
  const strs = (k: string): string[] => {
    if (!has(p, k) || p[k] === undefined) return [];
    const v = p[k];
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) return fail("invalid_option", `${k} must be an array of strings`);
    return v as string[];
  };
  const minLength = int("minLength", 12, 1);
  const maxLength = int("maxLength", 128, 1);
  if (minLength > maxLength) fail("invalid_option", "minLength is greater than maxLength");
  const rules = { lower: bool("requireLowercase", false), upper: bool("requireUppercase", false), digit: bool("requireDigit", false), symbol: bool("requireSymbol", false) };
  const maxRepeat = int("maxRepeat", 0, 0);
  const blocklist = bool("blocklist", true);
  const extra = strs("extraBlocklist");
  const inputs = strs("userInputs");
  if (typeof password !== "string") return fail("invalid_input", "password must be a string");

  const cps = Array.from(password);
  const v: string[] = [];
  if (cps.length < minLength) v.push("too_short");
  if (cps.length > maxLength) v.push("too_long");
  if (rules.lower && !/[a-z]/.test(password)) v.push("missing_lowercase");
  if (rules.upper && !/[A-Z]/.test(password)) v.push("missing_uppercase");
  if (rules.digit && !/[0-9]/.test(password)) v.push("missing_digit");
  if (rules.symbol && !/[!-/:-@[-`{-~]/.test(password)) v.push("missing_symbol");
  if (maxRepeat > 0) {
    let run = 1;
    for (let i = 1; i < cps.length; i++) {
      run = cps[i] === cps[i - 1] ? run + 1 : 1;
      if (run > maxRepeat) {
        v.push("repeated_characters");
        break;
      }
    }
  }
  const lower = asciiLower(password);
  if ((blocklist && COMMON_PASSWORDS.includes(lower)) || extra.some((e) => asciiLower(e) === lower)) v.push("common_password");
  if (inputs.some((u) => Array.from(u).length >= 3 && lower.includes(asciiLower(u)))) v.push("contains_user_input");
  return v;
}

// ---------------------------------------------------------------- rate limiting

export interface RateResult<S> {
  allowed: boolean;
  remaining: number;
  /** Milliseconds until a request can succeed; 0 when allowed. */
  retryAfter: number;
  state: S;
}

export interface FixedWindowConfig {
  limit: number;
  windowMs: number;
}
export interface FixedWindowState {
  windowStart: number;
  count: number;
}

const posInt = (v: unknown, what: string): number =>
  typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= MAX_SAFE ? v : fail("invalid_option", `${what} must be an integer >= 1`);
const timeOf = (v: unknown): number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE ? v : fail("invalid_option", "now must be a non-negative integer");

function stateNums(state: unknown, keys: string[]): number[] | null {
  if (state === null || state === undefined) return null;
  if (!isObject(state)) return fail("invalid_option", "state must be an object");
  return keys.map((k) => {
    const v = state[k];
    return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE ? v : fail("invalid_option", `state.${k} must be a non-negative integer`);
  });
}

/** Fixed window aligned to multiples of `windowMs`. */
export function fixedWindow(state: FixedWindowState | null, now: number, config: FixedWindowConfig): RateResult<FixedWindowState> {
  if (!isObject(config)) return fail("invalid_option", "config must be an object");
  const limit = posInt(config.limit, "limit");
  const windowMs = posInt(config.windowMs, "windowMs");
  const t = timeOf(now);
  const s = stateNums(state, ["windowStart", "count"]);
  const windowStart = t - (t % windowMs);
  let count = s !== null && s[0] === windowStart ? (s[1] as number) : 0;
  const allowed = count < limit;
  if (allowed) count++;
  return { allowed, remaining: Math.max(0, limit - count), retryAfter: allowed ? 0 : windowStart + windowMs - t, state: { windowStart, count } };
}

export interface TokenBucketConfig {
  capacity: number;
  refillTokens: number;
  refillIntervalMs: number;
  cost?: number;
}
export interface TokenBucketState {
  tokens: number;
  updatedAt: number;
}

/** Token bucket with integer refill: `refillTokens` every `refillIntervalMs`. */
export function tokenBucket(state: TokenBucketState | null, now: number, config: TokenBucketConfig): RateResult<TokenBucketState> {
  if (!isObject(config)) return fail("invalid_option", "config must be an object");
  const capacity = posInt(config.capacity, "capacity");
  const refill = posInt(config.refillTokens, "refillTokens");
  const interval = posInt(config.refillIntervalMs, "refillIntervalMs");
  const cost = config.cost === undefined ? 1 : posInt(config.cost, "cost");
  if (cost > capacity) return fail("invalid_option", "cost must not exceed capacity");
  const t = timeOf(now);
  const s = stateNums(state, ["tokens", "updatedAt"]);
  let tokens = s === null ? capacity : Math.min(s[0] as number, capacity);
  let updatedAt = s === null ? t : (s[1] as number);
  if (t > updatedAt) {
    const intervals = Math.floor((t - updatedAt) / interval);
    tokens = Math.min(capacity, tokens + intervals * refill);
    updatedAt = tokens === capacity ? t : updatedAt + intervals * interval;
  }
  if (tokens >= cost) {
    tokens -= cost;
    return { allowed: true, remaining: tokens, retryAfter: 0, state: { tokens, updatedAt } };
  }
  const need = Math.ceil((cost - tokens) / refill);
  const elapsed = t > updatedAt ? t - updatedAt : 0;
  return { allowed: false, remaining: tokens, retryAfter: need * interval - elapsed, state: { tokens, updatedAt } };
}

/** Run one limiter over a sequence of request times; returns `{allowed, remaining, retryAfter}` per request. */
export function simulateRateLimit(kind: unknown, config: unknown, times: unknown): { allowed: boolean; remaining: number; retryAfter: number }[] {
  if (kind !== "fixedWindow" && kind !== "tokenBucket") return fail("invalid_option", "kind must be fixedWindow or tokenBucket");
  if (!Array.isArray(times)) return fail("invalid_option", "times must be an array");
  const out: { allowed: boolean; remaining: number; retryAfter: number }[] = [];
  let state: FixedWindowState | TokenBucketState | null = null;
  for (const now of times) {
    const r: RateResult<FixedWindowState | TokenBucketState> =
      kind === "fixedWindow"
        ? fixedWindow(state as FixedWindowState | null, now as number, config as FixedWindowConfig)
        : tokenBucket(state as TokenBucketState | null, now as number, config as TokenBucketConfig);
    state = r.state;
    out.push({ allowed: r.allowed, remaining: r.remaining, retryAfter: r.retryAfter });
  }
  return out;
}

// ---------------------------------------------------------------- contract entry point

function argBytes(v: unknown): string | Bytes {
  if (isObject(v) && typeof v["hex"] === "string" && Object.keys(v).length === 1) {
    const b = fromHex(v["hex"] as string);
    if (b === null) return fail("invalid_input", "invalid hex");
    return b;
  }
  return v as string;
}

/** Dynamic entry point with the contract's JSON calling convention; `{ "hex": "..." }` denotes bytes. */
export function call(fn: string, args: unknown[]): unknown {
  const a = (i: number): unknown => args[i];
  switch (fn) {
    case "sha256Hex": return sha256Hex(argBytes(a(0)));
    case "hmacSha256Hex": return hmacSha256Hex(argBytes(a(0)), argBytes(a(1)));
    case "timingSafeEqual": return timingSafeEqual(argBytes(a(0)), argBytes(a(1)));
    case "createCsrfToken": return createCsrfToken(argBytes(a(0)), a(1) as string, a(2) as string | null | undefined);
    case "verifyCsrfToken": return verifyCsrfToken(argBytes(a(0)), a(1), a(2) as string | null | undefined);
    case "securityHeaders": return securityHeaders(a(0) as Record<string, string | null> | null | undefined);
    case "buildCsp": return buildCsp(a(0) as Record<string, string[] | true>);
    case "escapeHtml": return escapeHtml(a(0) as string);
    case "safeRedirect": return safeRedirect(a(0), a(1) as RedirectOptions | null | undefined);
    case "checkPassword": return checkPassword(a(0), a(1) as PasswordPolicy | null | undefined);
    case "simulateRateLimit": return simulateRateLimit(a(0), a(1), a(2));
    default: return fail("invalid_option", `unknown function: ${fn}`);
  }
}
