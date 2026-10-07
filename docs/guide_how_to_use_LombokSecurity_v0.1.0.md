# Guide How To Use LombokSecurity v0.1.0

## Instalasi

Belum terbit. Setelah rilis: `npm install lomboksecurity` atau `cargo add lomboksecurity`. Sebelum itu, bangun dari repo (lihat `CONTRIBUTING.md`).

## Konsep dasar

1. Semua fungsi murni. Keacakan (nonce CSRF) dan waktu (rate limiter) dipasok pemanggil; di TypeScript `generateCsrfToken` memakai `crypto.getRandomValues`.
2. Secret disimpan di konfigurasi, paling sedikit 16 byte (disarankan 32 byte acak).
3. Fungsi verifikasi mengembalikan boolean tanpa alasan; fungsi konfigurasi melempar galat dengan `code`.

## Contoh

```ts
import { generateCsrfToken, verifyCsrfToken } from "lomboksecurity";

// saat merender formulir
const token = generateCsrfToken(secret, session.id);
// saat menerima POST
if (!verifyCsrfToken(secret, body._csrf, session.id)) return reply(403);
```

## Recipes

### CSP tervalidasi

```ts
import { buildCsp, securityHeaders } from "lomboksecurity";
const csp = buildCsp({ "default-src": ["'self'"], "img-src": ["'self'", "data:"], "upgrade-insecure-requests": true });
// default-src 'self'; img-src 'self' data:; upgrade-insecure-requests
const headers = securityHeaders({ "Content-Security-Policy": csp });
```

### Redirect setelah login

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

Dengan `{ limit: 2, windowMs: 60000 }` dan permintaan pada 0, 1000, 2000 ms, permintaan ketiga ditolak dengan `retryAfter` 58000.

### Pemeriksaan kata sandi saat pendaftaran

```ts
import { checkPassword } from "lomboksecurity";
const problems = checkPassword(pw, { userInputs: [email, username], extraBlocklist: ["namaaplikasi2026"] });
```

## Common pitfalls

- Nonce CSRF di port Rust harus berasal dari sumber acak yang aman (misalnya `getrandom` di aplikasi), bukan dari waktu.
- Ikat token CSRF ke sesi lewat `context`; token tanpa konteks dapat dipakai ulang lintas sesi.
- `safeRedirect` membandingkan host persis; subdomain tidak otomatis diizinkan.
- `retryAfter` dalam milidetik; header HTTP `Retry-After` dalam detik.
- `checkPassword` bawaan tidak mewajibkan komposisi (sesuai NIST SP 800-63B); aktifkan `require*` hanya bila kebijakan organisasi menuntut.
- `escapeHtml` untuk teks dan atribut berkutip; bukan untuk konteks JavaScript, CSS, atau URL.

## Lihat juga

README, SPEC_, API_.
