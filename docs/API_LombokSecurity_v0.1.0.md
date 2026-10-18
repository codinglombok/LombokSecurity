# API LombokSecurity v0.1.0

Normative semantics are in `SPEC_LombokSecurity_v0.1.0.md`; this document only lists the interfaces that are actually exported.

## 1. TypeScript (package `lomboksecurity`)

Stability: 0.x, may change in minor releases. `Bytes` is `Uint8Array`; string arguments are read as UTF-8.

| Symbol | Signature | Notes |
|---|---|---|
| `sha256Hex` | `(data: string \| Bytes) => string` | Since 0.1.0 |
| `hmacSha256Hex` | `(key: string \| Bytes, data: string \| Bytes) => string` | |
| `timingSafeEqual` | `(a: string \| Bytes, b: string \| Bytes) => boolean` | |
| `createCsrfToken` | `(secret, nonceHex: string, context?: string \| null) => string` | |
| `verifyCsrfToken` | `(secret, token: unknown, context?: string \| null) => boolean` | |
| `generateCsrfToken` | `(secret, context?) => string` | Uses `globalThis.crypto.getRandomValues` |
| `securityHeaders` | `(overrides?: Record<string, string \| null> \| null) => [string, string][]` | |
| `buildCsp` | `(directives: Record<string, string[] \| true>) => string` | |
| `escapeHtml` | `(text: string) => string` | |
| `safeRedirect` | `(target: unknown, options?: { allowedHosts?: string[]; fallback?: string }) => string` | |
| `checkPassword` | `(password: unknown, policy?: PasswordPolicy) => string[]` | |
| `fixedWindow` | `(state, now, { limit, windowMs }) => RateResult<FixedWindowState>` | |
| `tokenBucket` | `(state, now, { capacity, refillTokens, refillIntervalMs, cost? }) => RateResult<TokenBucketState>` | |
| `simulateRateLimit` | `(kind, config, times) => { allowed; remaining; retryAfter }[]` | |
| `call` | `(fn: string, args: unknown[]) => unknown` | Contract entry point; `{hex}` means bytes |
| `DEFAULT_HEADERS`, `COMMON_PASSWORDS`, `MIN_SECRET_BYTES` | constants | |
| `utf8`, `toHex`, `fromHex`, `base64`, `base64Decode`, `base64url`, `base64urlDecode`, `sha256`, `hmacSha256`, `constantTimeEqual` | primitives | From `crypto.ts` |
| `LombokSecurityError` | `extends Error`; `code`, `messageId` | Codes: SPEC section 11 |

## 2. Rust (crate `lomboksecurity`)

Feature: `std` (default). Without `std`, the crate is `no_std + alloc`.

| Symbol | Notes |
|---|---|
| `sha256_hex`, `hmac_sha256_hex`, `timing_safe_equal` | Hashing |
| `create_csrf_token(&[u8], &str, Option<&str>)`, `verify_csrf_token(...)` | CSRF; the nonce is supplied by the caller |
| `security_headers(&[(&str, Option<&str>)])`, `DEFAULT_HEADERS` | Headers |
| `build_csp(&[(&str, CspValue)])`, `CspValue` (`Flag`, `Sources`) | CSP |
| `escape_html(&str)` | |
| `safe_redirect(&str, &RedirectOptions)`, `RedirectOptions { allowed_hosts, fallback }` | |
| `check_password(&str, &PasswordPolicy)`, `PasswordPolicy`, `COMMON_PASSWORDS` | |
| `fixed_window(...)`, `token_bucket(...)`, `RateResult`, `FixedWindowState`, `TokenBucketState`, `TokenBucketConfig` | |
| `call(fn, args)` | Contract entry point |
| `crypto::{sha1, sha256, hmac_sha1, hmac_sha256, pbkdf2_sha256, to_hex, from_hex, base64, base64_decode, base64url, base64url_decode, constant_time_eq}` | Primitives |
| `Error { code, message }` | `message_id()` |

## 3. Other ports

None yet.

## 4. Cross-language compatibility

For the same input, TypeScript and Rust produce identical results on all vectors (341 cases).
