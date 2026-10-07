# Changelog

Semua perubahan penting dicatat di sini. Format mengikuti [Keep a Changelog](https://keepachangelog.com/); entri terbaru di depan. Versi mengikuti [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-07

### Added
- SHA-256, HMAC-SHA256, dan perbandingan waktu-konstan tanpa dependensi (diverifikasi terhadap FIPS 180-4, RFC 4231, dan `node:crypto`).
- Token CSRF bertanda tangan HMAC dengan pengikatan konteks sesi.
- `securityHeaders` dengan tujuh header bawaan dan `buildCsp` tervalidasi.
- `escapeHtml`, `safeRedirect` (perlindungan open redirect), dan `checkPassword` (gaya NIST SP 800-63B).
- Rate limiter `fixedWindow` dan `tokenBucket` dengan aritmetika bilangan bulat dan status eksplisit.
- Port Rust (`no_std + alloc`, tanpa dependensi, modul `crypto` publik) dan port TypeScript (tanpa dependensi runtime).
- Vector bersama 341 kasus (181 golden berekspektasi tulis tangan atau dari standar, 160 regresi hasil pembangkit), dijalankan oleh runner Rust dan TypeScript.
- Pseudo-fuzz dan skrip uji mutasi (25 mutan).

### Security
- Perbandingan tanda tangan waktu-konstan.
- Penolakan CR/LF di header dan `;` di sumber CSP.
- `safeRedirect` menolak `//host`, backslash, userinfo, dan host di luar daftar.
