# Full Summary LombokSecurity v0.1.0

## What it is

Dependency-free web security primitives: hashing and HMAC, CSRF tokens, security headers and CSP, HTML escaping, safe redirects, a password policy, and rate limiting.

## Why it exists

Web vulnerabilities most often come from small details that are reimplemented in every project and every language: token comparison that is not constant-time, headers that can have a newline injected, a redirect to `//host` that is treated as local, and a CSP assembled without validation. A shared contract makes those details the same and tested in every port.

## Main features

See the README (Features section). All features are covered by vectors.

## Current status

Complete code for Rust and TypeScript; passes 341 vector cases; not yet published to any registry; does not yet meet the release score rule (see `TECH_DEBT.md`).

## Example users

See the README (usage scenarios).

## Known Limitations

- Not a general-purpose cryptography library; no encryption or password hashing.
- The SHA-256 and HMAC implementations have not been audited by a third party.
- The Rust port has no source of randomness.
- `safeRedirect` does not normalize IDNs or percent-encoding in the host.
- The built-in common-password list has only 40 entries.
- Only two ports (Rust, TypeScript); fuzzing is pseudo-fuzzing, not `cargo-fuzz`; no third-party audit; coverage not measured yet.

## More information

`SPEC_`, `API_`, `development_ide_`.

## Gap vs comparators (U6)

The comparison is qualitative and based on general knowledge of each category of library; it has not been verified feature by feature on 2026-10-07.

| Comparator (category) | What the comparator has that LombokSecurity does not | What LombokSecurity offers |
|---|---|---|
| Security middleware (helmet, csurf, express-rate-limit, Django security middleware) | Framework integration, shared state storage, wide configuration | A cross-language contract with shared vectors; pure functions; a `no_std + alloc` core; no dependencies |
| Cryptography libraries (ring, RustCrypto, WebCrypto) | A wide range of algorithms, audits, hardware optimization | Only the primitives that are needed, no dependencies, identical output across ports |
