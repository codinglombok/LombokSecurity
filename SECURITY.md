# Security Policy

## Supported versions

| Version | Support |
|---|---|
| 0.1.x | Security fixes |

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** on this repository (Security tab, "Report a vulnerability"). Do not open a public issue for a vulnerability.

- Initial response: within 48 hours.
- Fix for critical findings: 7 days (target).
- Disclosure is coordinated with the reporter.

## Scope

In scope: every exported function, in particular CSRF token forgery, timing leaks in comparisons, headers that can have a newline injected, open redirects that get past `safeRedirect`, text that gets past `escapeHtml`, and panics or unbounded execution time.

Out of scope: sources of randomness supplied by the application, out-of-process storage of rate limiter state, and web server configuration.

## Short threat model

See section 10 of `docs/SPEC_LombokSecurity_v0.1.0.md`.
