# LombokSecurity

[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)

Primitif keamanan web tanpa dependensi: **SHA-256 dan HMAC**, **token CSRF** bertanda tangan, **header keamanan** dan **CSP**, **escape HTML**, **perlindungan open redirect**, **kebijakan kata sandi** gaya NIST SP 800-63B, dan **rate limiting** (fixed window dan token bucket). Fungsi murni: keacakan dan waktu dipasok pemanggil. Hasilnya identik di setiap port.

Part of the [Lombok Ecosystem](https://github.com/codinglombok).

## Mengapa library ini?

Kesalahan keamanan web jarang berasal dari algoritma yang rumit; biasanya dari detail kecil: perbandingan token yang bocor lewat waktu, header yang dapat disisipi baris baru, redirect ke `//evil.example.net` yang dianggap jalur lokal, atau CSP yang disusun dari string tanpa validasi. LombokSecurity menetapkan detail itu secara normatif dan membuktikannya dengan vector bersama, termasuk vector standar FIPS 180-4 dan RFC 4231.

Skenario pemakaian:

- **Layanan web dan API**: token CSRF terikat sesi, header keamanan bawaan, CSP tervalidasi, redirect setelah login yang aman.
- **Formulir pendaftaran**: pemeriksaan kata sandi berbasis panjang dan daftar kata sandi umum.
- **Gateway dan API publik**: rate limiter fixed window atau token bucket dengan status yang dapat disimpan di mana saja.
- **Serverless dan edge**: tanpa dependensi dan tanpa I/O.
- **Perangkat tertanam**: inti Rust `no_std + alloc` dengan HMAC-SHA256 sendiri.

Contoh dependen lain di ekosistem Lombok dicantumkan di `docs/map_LombokSecurity_v0.1.0.md`.

## Fitur

Setiap fitur di bawah ini dicakup vector di `vectors/` dan test TypeScript.

- `sha256Hex`, `hmacSha256Hex`, `timingSafeEqual` (implementasi sendiri, diverifikasi terhadap FIPS 180-4, RFC 4231, dan `node:crypto`).
- `createCsrfToken`, `verifyCsrfToken` (HMAC-SHA256 atas nonce dan konteks sesi), `generateCsrfToken` (TypeScript, `crypto.getRandomValues`).
- `securityHeaders`: tujuh header bawaan yang dapat diganti, dihapus, atau ditambah; penolakan CR, LF, dan karakter kontrol.
- `buildCsp`: serialisasi direktif dengan penolakan `;`, `,`, dan spasi di sumber.
- `escapeHtml`: lima karakter `& < > " '`.
- `safeRedirect`: jalur lokal atau URL http(s) ke host yang diizinkan; selain itu fallback.
- `checkPassword`: panjang, komposisi opsional, karakter berulang, daftar kata sandi umum, dan kemiripan dengan data pengguna.
- `fixedWindow`, `tokenBucket`, `simulateRateLimit`: aritmetika bilangan bulat, status eksplisit.

## Instalasi

Belum terbit di registry. Setelah rilis pertama:

```bash
npm install lomboksecurity      # TypeScript / JavaScript
cargo add lomboksecurity        # Rust
```

## Quick Start

### TypeScript

```ts
import { generateCsrfToken, verifyCsrfToken, safeRedirect, securityHeaders, checkPassword } from "lomboksecurity";

const secret = process.env.CSRF_SECRET!;                 // paling sedikit 16 byte
const token = generateCsrfToken(secret, sessionId);      // taruh di formulir
verifyCsrfToken(secret, submittedToken, sessionId);      // true atau false

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

## Status port

| Port | Status | Bukti |
|---|---|---|
| Rust (`no_std + alloc`) | YA, lulus vector | `rust/tests/vectors.rs` menjalankan seluruh vector; uji known-answer SHA-1, HMAC-SHA1, PBKDF2; build `thumbv7em-none-eabi` |
| TypeScript | YA, lulus vector | `typescript/test/vectors.test.ts` menjalankan seluruh vector; kripto dibandingkan dengan `node:crypto` pada masukan acak; fuzz `safeRedirect` |
| Python, Go, PHP, Java, Kotlin, C#, C/C++, Swift, Perl | BELUM | Tidak ada kode; direncanakan setelah kontrak stabil (lihat `docs/development_ide_LombokSecurity_v0.1.0.md`) |

Vector: 341 kasus (181 golden berekspektasi tulis tangan atau dari standar, 160 regresi hasil pembangkit).

## Standar yang diimplementasikan

FIPS 180-4 (SHA-256), RFC 2104 dan RFC 4231 (HMAC-SHA256), RFC 9110 (sintaks nama header), CSP Level 3 (sintaks serialisasi), NIST SP 800-63B (panduan kata sandi), RFC 6585 (konvensi `Retry-After` untuk status 429). Lihat `docs/SPEC_LombokSecurity_v0.1.0.md`.

## Batasan yang diketahui

- Bukan pustaka kriptografi umum: tidak ada enkripsi, tanda tangan asimetris, atau KDF modern (Argon2). Untuk itu pakai LombokEncryptDecrypt atau pustaka khusus.
- Implementasi SHA-256 dan HMAC belum diaudit pihak ketiga dan belum diuji terhadap serangan side-channel selain perbandingan waktu konstan.
- Port Rust tidak memiliki sumber keacakan; nonce CSRF dipasok pemanggil.
- `safeRedirect` tidak menormalisasi IDN atau persen-encoding host; host dibandingkan apa adanya setelah huruf kecil ASCII.
- Daftar kata sandi umum bawaan kecil (40 entri); tambahkan daftar sendiri lewat `extraBlocklist`.
- Status rate limiter disimpan pemanggil; tidak ada penyimpanan bersama antar proses.
- Hanya Rust dan TypeScript yang memiliki kode. Fuzz bersifat pseudo-fuzz, belum `cargo-fuzz`.

## Ekosistem Lombok

LombokSecurity tidak bergantung pada library Lombok lain (L0). Library lain dapat memakainya secara opsional; daftar dependen ada di `docs/map_LombokSecurity_v0.1.0.md`.

## Contributing

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Untuk melaporkan kerentanan lihat [SECURITY.md](SECURITY.md).

## Lisensi

`Apache-2.0 OR MIT`. Lihat [LICENSE-APACHE](LICENSE-APACHE) dan [LICENSE-MIT](LICENSE-MIT).
