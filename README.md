# LombokSecurity

[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)

Dependency-free web security primitives: **SHA-256 and HMAC**, signed **CSRF tokens**, **security headers** and **CSP**, **HTML escaping**, **open-redirect protection**, an NIST SP 800-63B style **password policy**, and **rate limiting** (fixed window and token bucket). Pure functions: randomness and time are supplied by the caller. The output is identical in every port.

Part of the [Lombok Ecosystem](https://github.com/codinglombok).

## Why this library?

Web security mistakes rarely come from complicated algorithms; they usually come from small details: a token comparison that leaks through timing, a header that can have a newline injected, a redirect to `//evil.example.net` that is treated as a local path, or a CSP assembled from strings without validation. LombokSecurity specifies those details normatively and proves them with shared vectors, including the standard vectors of FIPS 180-4 and RFC 4231.

Usage scenarios:

- **Web services and APIs**: session-bound CSRF tokens, default security headers, a validated CSP, and safe post-login redirects.
- **Registration forms**: password checks based on length and a list of common passwords.
- **Gateways and public APIs**: a fixed-window or token-bucket rate limiter whose state can be stored anywhere.
- **Serverless and edge**: no dependencies and no I/O.
- **Embedded devices**: a `no_std + alloc` Rust core with its own HMAC-SHA256.

Other dependents in the Lombok Ecosystem are listed in `docs/map_LombokSecurity_v0.1.0.md`.

## Features

Every feature below is covered by vectors in `vectors/` and by TypeScript tests.

- `sha256Hex`, `hmacSha256Hex`, `timingSafeEqual` (own implementation, verified against FIPS 180-4, RFC 4231 and `node:crypto`).
- `createCsrfToken`, `verifyCsrfToken` (HMAC-SHA256 over a nonce and the session context), `generateCsrfToken` (TypeScript, `crypto.getRandomValues`).
- `securityHeaders`: seven default headers that can be replaced, removed or extended; CR, LF and control characters are rejected.
- `buildCsp`: directive serialization that rejects `;`, `,` and whitespace in sources.
- `escapeHtml`: the five characters `& < > " '`.
- `safeRedirect`: a local path or an http(s) URL to an allowed host; anything else falls back.
- `checkPassword`: length, optional composition rules, repeated characters, a list of common passwords, and similarity to user data.
- `fixedWindow`, `tokenBucket`, `simulateRateLimit`: integer arithmetic with explicit state.

## Installation

Not published to any registry yet. After the first release:

```bash
npm install lomboksecurity      # TypeScript / JavaScript
cargo add lomboksecurity        # Rust
```

## Quick Start

### TypeScript

```ts
import { generateCsrfToken, verifyCsrfToken, safeRedirect, securityHeaders, checkPassword } from "lomboksecurity";

const secret = process.env.CSRF_SECRET!;                 // at least 16 bytes
const token = generateCsrfToken(secret, sessionId);      // put it in the form
verifyCsrfToken(secret, submittedToken, sessionId);      // true or false

safeRedirect("//evil.example.net/x");                     // "/"
safeRedirect("https://app.example.com/home", { allowedHosts: ["app.example.com"] });
checkPassword("password");                                // ["too_short", "common_password"]
for (const [name, value] of securityHeaders({ "X-Frame-Options": "SAMEORIGIN" })) res.setHeader(name, value);
```

### Rust

```rust
use lomboksecurity::{create_csrf_token, verify_csrf_token, escape_html};

let secret = b"0123456789abcdef0123456789abcdef";
let token = create_csrf_token(secret, "00112233445566778899aabbccddeeff", Some("session-1")).unwrap();
assert!(verify_csrf_token(secret, &token, Some("session-1")).unwrap());
assert_eq!(escape_html("<b>\"x\"</b>"), "&lt;b&gt;&quot;x&quot;&lt;/b&gt;");
```

## Port status

| Port | Status | Evidence |
|---|---|---|
| Rust (`no_std + alloc`) | YES, passes the vectors | `rust/tests/vectors.rs` runs every vector; known-answer tests for SHA-1, HMAC-SHA1 and PBKDF2; `thumbv7em-none-eabi` build |
| TypeScript | YES, passes the vectors | `typescript/test/vectors.test.ts` runs every vector; the cryptography is compared with `node:crypto` on random inputs; `safeRedirect` fuzzing |
| Python, Go, PHP, Java, Kotlin, C#, C/C++, Swift, Perl | NOT YET | No code; planned once the contract is stable (see `docs/development_ide_LombokSecurity_v0.1.0.md`) |

Vectors: 341 cases (181 golden cases with hand-written or standard expectations, 160 generated regression cases).

## Standards implemented

FIPS 180-4 (SHA-256), RFC 2104 and RFC 4231 (HMAC-SHA256), RFC 9110 (header name syntax), CSP Level 3 (serialization syntax), NIST SP 800-63B (password guidance), RFC 6585 (the `Retry-After` convention for status 429). See `docs/SPEC_LombokSecurity_v0.1.0.md`.

## Known limitations

- Not a general-purpose cryptography library: there is no encryption, no asymmetric signatures and no modern KDF (Argon2). Use LombokEncryptDecrypt or a dedicated library for those.
- The SHA-256 and HMAC implementations have not been audited by a third party and have not been tested against side-channel attacks other than the constant-time comparison.
- The Rust port has no source of randomness; the CSRF nonce is supplied by the caller.
- `safeRedirect` does not normalize IDNs or percent-encoding in the host; the host is compared as is after ASCII lowercasing.
- The built-in common-password list is small (40 entries); add your own list through `extraBlocklist`.
- Rate limiter state is stored by the caller; there is no shared storage between processes.
- Only Rust and TypeScript have code. Fuzzing is pseudo-fuzzing, not `cargo-fuzz`.

## Lombok Ecosystem

LombokSecurity has no required dependency on other Lombok libraries (L0). Other libraries may use it optionally; the dependents are listed in `docs/map_LombokSecurity_v0.1.0.md`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

`Apache-2.0 OR MIT`. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
