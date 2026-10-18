# Development IDE LombokSecurity v0.1.0

## 1. Roadmap

| Version | Content |
|---|---|
| 0.1.1 | Close the release conditions: CI run, `doctor docs/privacy/style`, coverage measured, a `cargo-fuzz` target |
| 0.2.0 | Whitelist-based HTML sanitization; a CORS helper; a sliding-window limiter; a larger common-password list as separate data; Python, Go and PHP ports |
| 0.3.0 | Third-party audit of the cryptography module; IDN normalization in `safeRedirect`; optional LombokCache integration |

## 2. Deferred scope

See the Non-goals section of the SPEC and the README (Known limitations).

## 3. Design principles for contributors

- Contract first, tests first; all ports pass the same vectors.
- No runtime dependencies; dev dependencies are recorded.
- Core functions are pure: the clock, randomness and I/O are supplied by the caller.
- Verification functions return a boolean without leaking the reason.
- Every value that ends up in a header or a policy is validated against injection.
- English is the default language for all documents, code comments and messages.

## 4. How to contribute

See `CONTRIBUTING.md`.

## 5. Open questions

- Does the CSRF token need an embedded expiry (a timestamp) in addition to session binding?
- Should `safeRedirect` accept subdomain patterns (`*.example.com`)?
