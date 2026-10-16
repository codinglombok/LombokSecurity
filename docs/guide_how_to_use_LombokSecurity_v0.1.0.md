# Guide How To Use LombokSecurity v0.1.0

## Installation

Not published yet. After the release: `npm install lomboksecurity` or `cargo add lomboksecurity`. Until then, build from the repository (see `CONTRIBUTING.md`).

## Basic concepts

1. All functions are pure. Randomness (the CSRF nonce) and time (the rate limiter) are supplied by the caller; in TypeScript, `generateCsrfToken` uses `crypto.getRandomValues`.
2. The secret lives in configuration and is at least 16 bytes (32 random bytes recommended).
3. Verification functions return a boolean without a reason; configuration functions throw an error with a `code`.

## Example

```ts
import { generateCsrfToken, verifyCsrfToken } from "lomboksecurity";

// when rendering the form
const token = generateCsrfToken(secret, session.id);
// when receiving the POST
if (!verifyCsrfToken(secret, body._csrf, session.id)) return reply(403);
```

## Recipes

### A validated CSP

```ts
import { buildCsp, securityHeaders } from "lomboksecurity";
const csp = buildCsp({ "default-src": ["'self'"], "img-src": ["'self'", "data:"], "upgrade-insecure-requests": true });
// default-src 'self'; img-src 'self' data:; upgrade-insecure-requests
const headers = securityHeaders({ "Content-Security-Policy": csp });
```

### A redirect after login

```ts
import { safeRedirect } from "lomboksecurity";
const next = safeRedirect(query.next, { allowedHosts: ["app.example.com"], fallback: "/dashboard" });
```

### Rate limit per IP

```ts
import { fixedWindow } from "lomboksecurity";
const r = fixedWindow(store.get(ip) ?? null, Date.now(), { limit: 100, windowMs: 60_000 });
store.set(ip, r.state);
if (!r.allowed) return reply(429, { "Retry-After": String(Math.ceil(r.retryAfter / 1000)) });
```

With `{ limit: 2, windowMs: 60000 }` and requests at 0, 1000 and 2000 ms, the third request is rejected with `retryAfter` 58000.

### Password check at registration

```ts
import { checkPassword } from "lomboksecurity";
const problems = checkPassword(pw, { userInputs: [email, username], extraBlocklist: ["appname2026"] });
```

## Common pitfalls

- In the Rust port, the CSRF nonce must come from a secure random source (for example `getrandom` in the application), not from the time.
- Bind the CSRF token to the session through `context`; a token without context can be reused across sessions.
- `safeRedirect` compares the host exactly; subdomains are not allowed automatically.
- `retryAfter` is in milliseconds; the HTTP header `Retry-After` is in seconds.
- By default, `checkPassword` does not require composition (in line with NIST SP 800-63B); enable `require*` only when the organization's policy demands it.
- `escapeHtml` is for text and quoted attributes; not for JavaScript, CSS or URL contexts.

## See also

README, SPEC_, API_.
