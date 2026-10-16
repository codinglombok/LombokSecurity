# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the newest entry comes first. Versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-07

### Added
- SHA-256, HMAC-SHA256 and constant-time comparison without dependencies (verified against FIPS 180-4, RFC 4231 and `node:crypto`).
- HMAC-signed CSRF tokens with session-context binding.
- `securityHeaders` with seven default headers and a validated `buildCsp`.
- `escapeHtml`, `safeRedirect` (open-redirect protection) and `checkPassword` (NIST SP 800-63B style).
- `fixedWindow` and `tokenBucket` rate limiters with integer arithmetic and explicit state.
- Rust port (`no_std + alloc`, no dependencies, public `crypto` module) and TypeScript port (no runtime dependencies).
- Shared vectors of 341 cases (181 golden cases with hand-written or standard expectations, 160 generated regression cases), executed by the Rust and TypeScript runners.
- Pseudo-fuzzing and a mutation-testing script (25 mutants).

### Security
- Constant-time signature comparison.
- Rejection of CR/LF in headers and of `;` in CSP sources.
- `safeRedirect` rejects `//host`, backslashes, userinfo and hosts outside the list.
