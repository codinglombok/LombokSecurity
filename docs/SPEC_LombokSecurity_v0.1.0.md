# SPEC LombokSecurity v0.1.0

This document is the normative cross-language contract. Every language port MUST produce byte-identical output for all specified inputs. Deviations from this specification are bugs.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in RFC 2119 and RFC 8174.

| Attribute | Value |
|---|---|
| Contract version | 0.1.0 |
| Review date of reference standards | 2026-10-07 |
| Vectors | `vectors/lomboksecurity-vectors-v1.json` |
| Vector SHA-256 | `bc39de3f3d6de49dc8e90d0bde1ff0ff571d2160477a58b4f83720f31ff9693f` |

## 0. Reference standards (U2)

| Reference | Version | Use |
|---|---|---|
| FIPS 180-4 | August 2015 | SHA-256 (and internal SHA-1) |
| RFC 2104, RFC 4231 | 1997, 2005 | HMAC and the HMAC-SHA256 test vectors |
| RFC 3629 | 2003 | UTF-8 encoding of string input |
| RFC 9110 | June 2022 | `token` syntax for header names |
| Content Security Policy Level 3 | W3C Working Draft 2024 | Directive serialization |
| NIST SP 800-63B | Revision 3 | Basis of the default password policy (length and blocklist) |
| RFC 6585 | 2012 | Status 429 and the meaning of `retryAfter` |
| RFC 2119, RFC 8174 | 1997, 2017 | Normative key words |

## 1. Vectors

The vector file contains `{ format, specVersion, note, groups }`. Each case contains `name`, `fn`, `args` and `expect` (`{ "result": ... }` or `{ "error": code }`). In `args`, an object `{ "hex": "..." }` means bytes; a string means its UTF-8 bytes. Every claimed port MUST run all cases through the entry point `call(fn, args)` and produce exactly the same result. The SHA-256 hash of the file MUST equal the one in the attribute table.

## 2. Hashing

`sha256Hex(data)` and `hmacSha256Hex(key, data)` produce lowercase hexadecimal. `timingSafeEqual(a, b)` is true when both byte sequences are equal; its duration MUST depend only on the length. An argument that is not a string or bytes, or an invalid `{hex}` (odd length, non-hexadecimal character), MUST produce `invalid_input`.

## 3. CSRF

`secret` is bytes (a string: UTF-8) of at least 16 bytes (otherwise `invalid_secret`). `nonce` MUST be exactly 32 lowercase hexadecimal digits (`invalid_nonce`). An optional `context` MUST be a string (`invalid_input`); absent or null is equivalent to the empty string.

`createCsrfToken(secret, nonce, context?)` = `nonce + "." + hex(HMAC-SHA256(secret, "csrf|" + nonce + "|" + context))`. Validation order: secret, nonce, context.

`verifyCsrfToken(secret, token, context?)`: after validating the secret and the context, a token that is not a string yields false. The token is split at the first `.`; the left part MUST match the nonce rule and the right part MUST be exactly 64 lowercase hexadecimal digits, otherwise false. The result is a constant-time comparison between the computed signature and the right part. This function MUST NOT throw for any token.

## 4. Security headers

Default headers, in order:

| Name | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

`securityHeaders(overrides?)`: absent or null `overrides` means the defaults; anything other than an object MUST produce `invalid_option`. Each key is processed in property order (ECMA-262): the name MUST be an RFC 9110 token (`invalid_header`); the value MUST be null or a string without U+0000..U+0008, U+000A..U+001F, U+007F (a tab is allowed; otherwise `invalid_header`). If the name equals an existing entry (ASCII case-insensitively), its value is replaced in place and the spelling of that entry's name is kept; otherwise the entry is appended at the end. An entry with the value null is removed from the result. The result is an array of `[name, value]` pairs.

## 5. CSP

`buildCsp(directives)`: an object (otherwise `invalid_csp`). Each directive in property order: the name MUST match `^[a-z][a-z0-9-]*$`; the value `true` produces the name only; an array value holds sources, each a non-empty string without the characters U+0000..U+0020, U+007F, `;`, `,`; an empty array produces the name only; any other value MUST produce `invalid_csp`. Directives are assembled as `name + " " + sources.join(" ")` and joined with `"; "`. An empty object produces an empty string.

## 6. HTML escaping

`escapeHtml(text)`: `&` becomes `&amp;`, `<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&quot;`, `'` becomes `&#39;`; other characters are unchanged. A non-string is `invalid_input`.

## 7. Safe redirect

Options: `allowedHosts` (an array of non-empty strings) and `fallback` (a local path, default `/`). Other keys or a wrong shape MUST produce `invalid_option`; options are validated before the target.

Unsafe characters: U+0000..U+0020, U+007F, and `\`. A **local path**: starts with `/`, does not start with `//`, and has no unsafe characters.

`safeRedirect(target, options?)` returns `fallback` unless:

1. `target` is a local path: it is returned as is.
2. `target` has no unsafe characters, starts with `http://` or `https://` (ASCII case-insensitively), and has an authority (the text after `://` up to `/`, `?`, `#` or the end) that is non-empty and has no `@`. The host is `[...]` up to the first `]` if the authority starts with `[`, otherwise the text before the first `:`; the rest of the authority MUST be empty or `:` followed by 1 to 5 digits. If the host (ASCII lowercase) equals one of `allowedHosts` (ASCII lowercase), `target` is returned as is.

A target that is not a string or is empty produces `fallback`.

## 8. Password policy

Policy (all optional): `minLength` (default 12, at least 1), `maxLength` (128, at least 1), `requireLowercase`, `requireUppercase`, `requireDigit`, `requireSymbol` (default false), `maxRepeat` (default 0 = off), `blocklist` (default true), `extraBlocklist`, `userInputs` (an array of strings). Unknown keys, wrong types, or `minLength > maxLength` MUST produce `invalid_option`; the policy is validated before the password; a password that is not a string MUST produce `invalid_input`.

`checkPassword` returns violation codes in the following order (length is counted per code point; character classes are ASCII only):

| Code | Condition |
|---|---|
| `too_short` | length < `minLength` |
| `too_long` | length > `maxLength` |
| `missing_lowercase` | required and there is no `a`-`z` |
| `missing_uppercase` | required and there is no `A`-`Z` |
| `missing_digit` | required and there is no `0`-`9` |
| `missing_symbol` | required and there is none of U+0021..U+002F, U+003A..U+0040, U+005B..U+0060, U+007B..U+007E |
| `repeated_characters` | `maxRepeat > 0` and there is a run of identical code points longer than `maxRepeat` |
| `common_password` | the ASCII-lowercase password equals an entry of the built-in list (if `blocklist`) or a lowercased `extraBlocklist` entry |
| `contains_user_input` | the ASCII-lowercase password contains the ASCII-lowercase form of one of the `userInputs` that is at least 3 code points long |

The built-in list is the 40 entries of `COMMON_PASSWORDS`, identical in all ports.

## 9. Rate limiting

All configuration values MUST be integers in 1..2^53-1 and times integers in 0..2^53-1 (`invalid_option`). State is supplied and returned by the caller.

**Fixed window** (`limit`, `windowMs`): `windowStart = now - now mod windowMs`. The count is the state's count if the state's `windowStart` is the same, otherwise 0. Allowed if count < `limit` (then count + 1). `remaining = max(0, limit - count)`. `retryAfter` is 0 if allowed, otherwise `windowStart + windowMs - now`.

**Token bucket** (`capacity`, `refillTokens`, `refillIntervalMs`, `cost` default 1, `cost <= capacity`): without state, tokens = `capacity` and `updatedAt = now`. If `now > updatedAt`: `k = floor((now - updatedAt) / refillIntervalMs)`, tokens = `min(capacity, tokens + k * refillTokens)`, then `updatedAt = now` if the bucket is full, otherwise `updatedAt + k * refillIntervalMs`. Allowed if tokens >= `cost` (tokens are reduced by `cost`; `retryAfter` is 0). Otherwise: `retryAfter = ceil((cost - tokens) / refillTokens) * refillIntervalMs - max(0, now - updatedAt)`. `remaining` is the tokens after the decision.

`simulateRateLimit(kind, config, times)`: `kind` is `fixedWindow` or `tokenBucket`, `times` is an array; it runs the limiter sequentially and returns `{ allowed, remaining, retryAfter }` per time. The configuration is validated at every step before the time.

## 10. Security

- Signature comparison MUST be constant-time; `verifyCsrfToken` MUST NOT leak the reason for a rejection.
- Headers and CSP MUST NOT be able to contain an injected line separator or directive separator.
- `safeRedirect` MUST NEVER return a target that leads to a host outside `allowedHosts`.
- Any input MUST produce a result or an error with a `code` from section 11; a panic or any other exception is a bug.

## 11. Errors

| `code` | Condition | `messageId` |
|---|---|---|
| `invalid_secret` | secret shorter than 16 bytes | `lomboksecurity.error.invalid_secret` |
| `invalid_nonce` | invalid nonce | `lomboksecurity.error.invalid_nonce` |
| `invalid_header` | invalid header name or value | `lomboksecurity.error.invalid_header` |
| `invalid_csp` | invalid CSP directive or source | `lomboksecurity.error.invalid_csp` |
| `invalid_option` | invalid option, policy or configuration; unknown function | `lomboksecurity.error.invalid_option` |
| `invalid_input` | argument of the wrong type or encoding | `lomboksecurity.error.invalid_input` |

## 12. Non-goals (0.1.0)

Encryption, asymmetric signatures, password hashing (see the authentication library), CORS, full HTML sanitization (tag whitelists), IDN normalization, and shared storage of rate limiter state.

## 13. Contract change history

| Version | Change |
|---|---|
| 0.1.0 | Initial contract |
