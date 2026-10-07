# Kebijakan Keamanan

## Versi yang didukung

| Versi | Dukungan |
|---|---|
| 0.1.x | Perbaikan keamanan |

## Melaporkan kerentanan

Gunakan **GitHub Private Vulnerability Reporting** pada repo ini (tab Security, "Report a vulnerability"). Jangan membuka issue publik untuk kerentanan.

- Respons awal: paling lama 48 jam.
- Perbaikan untuk temuan kritis: target 7 hari.
- Pengungkapan dikoordinasikan dengan pelapor.

## Cakupan

Dalam cakupan: seluruh fungsi yang diekspor, khususnya pemalsuan token CSRF, kebocoran waktu pada perbandingan, header yang dapat disisipi baris baru, pengalihan terbuka yang lolos `safeRedirect`, teks yang lolos `escapeHtml`, dan panic atau waktu eksekusi tak terbatas.

Di luar cakupan: sumber keacakan yang dipasok aplikasi, penyimpanan status rate limiter di luar proses, dan konfigurasi server web.

## Model ancaman ringkas

Lihat bagian Keamanan pada `docs/SPEC_LombokSecurity_v0.1.0.md`.
