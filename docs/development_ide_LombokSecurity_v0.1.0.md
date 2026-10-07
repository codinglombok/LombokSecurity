# Development IDE LombokSecurity v0.1.0

## 1. Roadmap

| Versi | Isi |
|---|---|
| 0.1.1 | Tutup syarat rilis: CI dijalankan, `doctor docs/privacy/style`, coverage diukur, target `cargo-fuzz` |
| 0.2.0 | Sanitasi HTML berbasis whitelist; helper CORS; sliding window limiter; daftar kata sandi umum yang lebih besar sebagai data terpisah; port Python, Go, PHP |
| 0.3.0 | Audit pihak ketiga untuk modul kripto; normalisasi IDN pada `safeRedirect`; integrasi opsional LombokCache |

## 2. Deferred scope

Lihat SPEC bagian Non-goals dan README (Batasan).

## 3. Prinsip desain kontributor

- Kontrak dulu, test dulu; semua port lulus vector yang sama.
- Tidak ada dependensi runtime; dev-dependency dicatat.
- Fungsi inti murni: jam, keacakan, dan I/O dipasok pemanggil.
- Fungsi verifikasi mengembalikan boolean tanpa membocorkan alasan.
- Setiap nilai yang berakhir di header atau kebijakan divalidasi terhadap penyisipan.

## 4. Cara berkontribusi

Lihat `CONTRIBUTING.md`.

## 5. Pertanyaan terbuka

- Apakah token CSRF perlu masa berlaku tertanam (stempel waktu) selain pengikatan sesi?
- Apakah `safeRedirect` sebaiknya menerima pola subdomain (`*.example.com`)?
