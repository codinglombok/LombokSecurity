# API LombokSecurity v0.1.0

Semantik normatif ada di `SPEC_LombokSecurity_v0.1.0.md`; dokumen ini hanya mendaftar antarmuka yang benar-benar diekspor.

## 1. TypeScript (paket `lomboksecurity`)

Stabilitas: 0.x, dapat berubah pada rilis minor. `Bytes` adalah `Uint8Array`; argumen string dibaca sebagai UTF-8.

| Simbol | Tanda tangan | Keterangan |
|---|---|---|
| `sha256Hex` | `(data: string \| Bytes) => string` | Sejak 0.1.0 |
| `hmacSha256Hex` | `(key: string \| Bytes, data: string \| Bytes) => string` | |
| `timingSafeEqual` | `(a: string \| Bytes, b: string \| Bytes) => boolean` | |
| `createCsrfToken` | `(secret, nonceHex: string, context?: string \| null) => string` | |
| `verifyCsrfToken` | `(secret, token: unknown, context?: string \| null) => boolean` | |
| `generateCsrfToken` | `(secret, context?) => string` | Memakai `globalThis.crypto.getRandomValues` |
| `securityHeaders` | `(overrides?: Record<string, string \| null> \| null) => [string, string][]` | |
| `buildCsp` | `(directives: Record<string, string[] \| true>) => string` | |
| `escapeHtml` | `(text: string) => string` | |
| `safeRedirect` | `(target: unknown, options?: { allowedHosts?: string[]; fallback?: string }) => string` | |
| `checkPassword` | `(password: unknown, policy?: PasswordPolicy) => string[]` | |
| `fixedWindow` | `(state, now, { limit, windowMs }) => RateResult<FixedWindowState>` | |
| `tokenBucket` | `(state, now, { capacity, refillTokens, refillIntervalMs, cost? }) => RateResult<TokenBucketState>` | |
| `simulateRateLimit` | `(kind, config, times) => { allowed; remaining; retryAfter }[]` | |
| `call` | `(fn: string, args: unknown[]) => unknown` | Titik masuk kontrak; `{hex}` berarti byte |
| `DEFAULT_HEADERS`, `COMMON_PASSWORDS`, `MIN_SECRET_BYTES` | konstanta | |
| `utf8`, `toHex`, `fromHex`, `base64`, `base64Decode`, `base64url`, `base64urlDecode`, `sha256`, `hmacSha256`, `constantTimeEqual` | primitif | Dari `crypto.ts` |
| `LombokSecurityError` | `extends Error`; `code`, `messageId` | Kode: SPEC bagian 11 |

## 2. Rust (crate `lomboksecurity`)

Fitur: `std` (bawaan). Tanpa `std`, crate bersifat `no_std + alloc`.

| Simbol | Keterangan |
|---|---|
| `sha256_hex`, `hmac_sha256_hex`, `timing_safe_equal` | Hashing |
| `create_csrf_token(&[u8], &str, Option<&str>)`, `verify_csrf_token(...)` | CSRF; nonce dipasok pemanggil |
| `security_headers(&[(&str, Option<&str>)])`, `DEFAULT_HEADERS` | Header |
| `build_csp(&[(&str, CspValue)])`, `CspValue` (`Flag`, `Sources`) | CSP |
| `escape_html(&str)` | |
| `safe_redirect(&str, &RedirectOptions)`, `RedirectOptions { allowed_hosts, fallback }` | |
| `check_password(&str, &PasswordPolicy)`, `PasswordPolicy`, `COMMON_PASSWORDS` | |
| `fixed_window(...)`, `token_bucket(...)`, `RateResult`, `FixedWindowState`, `TokenBucketState`, `TokenBucketConfig` | |
| `call(fn, args)` | Titik masuk kontrak |
| `crypto::{sha1, sha256, hmac_sha1, hmac_sha256, pbkdf2_sha256, to_hex, from_hex, base64, base64_decode, base64url, base64url_decode, constant_time_eq}` | Primitif |
| `Error { code, message }` | `message_id()` |

## 3. Port lain

Belum ada.

## 4. Kompatibilitas lintas bahasa

Untuk masukan yang sama, TypeScript dan Rust menghasilkan hasil identik pada seluruh vector (341 kasus).
