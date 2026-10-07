# Map LombokSecurity v0.1.0

## 1. Posisi dependensi

L0. Posisi cluster dan nomor katalog mengikuti dokumen induk ekosistem v3.6 (tidak di-commit, ADR-024). Tidak memiliki dependensi Lombok wajib.

## 2. Contoh dependen di ekosistem

Bagian ini satu-satunya tempat nama aplikasi atau framework boleh muncul (ADR-019). Ini ilustrasi, bukan kepemilikan; siapa pun dapat memakai LombokSecurity.

| Pemakai | Jenis | Status integrasi | Keterangan |
|---|---|---|---|
| LombokClarion v3 | Framework | rencana (F7) | Menggantikan logika CSRF, header keamanan, dan rate limit di paket security internal v2 |
| LombokAuth | Library | rencana (opsional) | Kebijakan kata sandi saat pendaftaran |
| LombokServer | Library L4 | rencana | Header keamanan dan rate limiting |
| LombokDocFlow | Aplikasi | rencana | Redirect aman dan CSRF |

Integrasi opsional ke LombokCache (penyimpanan status rate limiter) dan LombokLog (jejak audit pelanggaran) belum diimplementasikan.

## 3. Bergantung pada

Tidak ada.

## 4. Jalur kontrak normatif

`docs/SPEC_LombokSecurity_v0.1.0.md` -> `vectors/lomboksecurity-vectors-v1.json` (sha256 di SPEC) -> runner `rust/tests/vectors.rs` dan `typescript/test/vectors.test.ts`.

## 5. Peta folder

Lihat `structure_repo_LombokSecurity_v0.1.0.md`.
