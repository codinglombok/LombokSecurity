# Changelog LombokSecurity (summary)

The newest entry comes first. Details are in `CHANGELOG.md`.

## 0.1.0 - 2026-10-07

### Added
- Hashing, CSRF, headers and CSP, HTML escaping, safe redirects, password policy, rate limiting.
- Rust `no_std + alloc` port and TypeScript port.
- 341 vectors; runners in both ports; fuzzing and mutation testing.

### Security
- Constant-time signature comparison.
- Rejection of CR/LF in headers and of `;` in CSP sources.
- `safeRedirect` rejects `//host`, backslashes, userinfo and hosts outside the list.
