# Vectors

`lomboksecurity-vectors-v1.json` adalah kontrak uji lintas bahasa untuk LombokSecurity.

- SHA-256: `bc39de3f3d6de49dc8e90d0bde1ff0ff571d2160477a58b4f83720f31ff9693f` (harus sama dengan `docs/SPEC_LombokSecurity_v0.1.0.md`).
- Dibangkitkan oleh `scripts/gen-vectors.mjs`. Grup `golden`: ekspektasi ditulis tangan atau disalin dari FIPS 180-4 dan RFC 4231, lalu dicocokkan dengan port TypeScript saat pembangkitan; ekspektasi hash dan HMAC juga dihitung ulang dengan `node:crypto`. Grup `generated-regression`: masukan acak berbenih, ekspektasi dari port TypeScript (hash dicek dengan `node:crypto`) dan dikonfirmasi port Rust.
- Setiap kasus memanggil fungsi `fn` dengan `args`; `expect` berbentuk `{ "result": ... }` atau `{ "error": code }`.
- Setiap port yang diklaim MUST menjalankan seluruh kasus.
- Jumlah: 341 kasus (181 golden berekspektasi tulis tangan atau dari standar, 160 regresi hasil pembangkit).
