# Changelog LombokSecurity (ringkasan)

Entri terbaru di depan. Rincian ada di `CHANGELOG.md`.

## 0.1.0 - 2026-10-07

### Added
- Hashing, CSRF, header dan CSP, escape HTML, redirect aman, kebijakan kata sandi, rate limiting.
- Port Rust `no_std + alloc` dan port TypeScript.
- Vector 341 kasus; runner di kedua port; fuzz, uji mutasi.

### Security
- Perbandingan tanda tangan waktu-konstan.
- Penolakan CR/LF di header dan `;` di sumber CSP.
- `safeRedirect` menolak `//host`, backslash, userinfo, dan host di luar daftar.
