# Full Summary LombokSecurity v0.1.0

## Apa ini

Primitif keamanan web tanpa dependensi: hashing dan HMAC, token CSRF, header keamanan dan CSP, escape HTML, redirect aman, kebijakan kata sandi, dan rate limiting.

## Mengapa dibuat

Kerentanan web paling sering berasal dari detail kecil yang diimplementasikan ulang di setiap proyek dan setiap bahasa: perbandingan token yang tidak waktu-konstan, header yang dapat disisipi baris baru, redirect ke `//host` yang dianggap lokal, dan CSP yang disusun tanpa validasi. Kontrak bersama membuat detail itu sama dan teruji di semua port.

## Fitur utama

Lihat README (bagian Fitur). Semua fitur dicakup vector.

## Status saat ini

Kode lengkap untuk Rust dan TypeScript; lulus 341 kasus vector; belum terbit di registry; belum memenuhi aturan skor rilis (lihat `TECH_DEBT.md`).

## Contoh pemakai

Lihat README (skenario pemakaian).

## Batasan yang Diketahui

- Bukan pustaka kriptografi umum; tidak ada enkripsi atau hashing kata sandi.
- Implementasi SHA-256 dan HMAC belum diaudit pihak ketiga.
- Port Rust tidak memiliki sumber keacakan.
- `safeRedirect` tidak menormalisasi IDN atau persen-encoding host.
- Daftar kata sandi umum bawaan hanya 40 entri.
- Hanya dua port (Rust, TypeScript); fuzz berupa pseudo-fuzz, belum `cargo-fuzz`; belum audit pihak ketiga; coverage belum diukur.

## Info lanjut

SPEC_, API_, `development_ide_`.

## Gap vs pembanding (U6)

Perbandingan bersifat kualitatif dan berdasarkan pengetahuan umum tentang kategori library; belum diverifikasi fitur demi fitur pada 2026-10-07.

| Pembanding (kategori) | Yang dimiliki pembanding dan belum dimiliki LombokSecurity | Yang ditawarkan LombokSecurity |
|---|---|---|
| Middleware keamanan (helmet, csurf, express-rate-limit, Django security middleware) | Integrasi framework, penyimpanan status bersama, konfigurasi yang luas | Kontrak lintas bahasa dengan vector bersama; fungsi murni; inti `no_std + alloc`; tanpa dependensi |
| Pustaka kripto (ring, RustCrypto, WebCrypto) | Algoritma luas, audit, optimasi perangkat keras | Hanya primitif yang dibutuhkan, tanpa dependensi, keluaran identik antar port |
