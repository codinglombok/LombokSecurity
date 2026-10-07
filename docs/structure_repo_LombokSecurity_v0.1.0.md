# Structure Repo LombokSecurity v0.1.0

## 1. Struktur folder

```
LombokSecurity/
  README.md  CHANGELOG.md  SECURITY.md  CONTRIBUTING.md  version.txt
  LICENSE-APACHE  LICENSE-MIT  .gitignore  .gitattributes
  docs/            10 dokumen standar + TECH_DEBT.md (masterplan_ dan architecture_ tidak di-commit)
  vectors/         lomboksecurity-vectors-v1.json  README.md
  locales/         en/lomboksecurity.json  id/lomboksecurity.json
  rust/            Cargo.toml  src/{lib.rs,crypto.rs,json.rs}  tests/vectors.rs  LICENSE-*
  typescript/      package.json  tsconfig*.json  src/  test/
  scripts/         gen-vectors.mjs  mutation-test.mjs  run-ts-tests.mjs
  .github/workflows/  ci.yml
```

## 2. Konvensi penamaan

Dokumen: `<jenis>_LombokSecurity_v<semver>.md`. Paket: npm `lomboksecurity`, crates.io `lomboksecurity`. Go (rencana): `github.com/codinglombok/lomboksecurity/go`.

## 3. Berkas wajib di root

README, LICENSE-APACHE, LICENSE-MIT, CHANGELOG, SECURITY, CONTRIBUTING, `.gitignore` dengan tiga baris ADR-024, `version.txt`.

## 4. Struktur per port

| Port | Isi |
|---|---|
| `rust/` | Satu crate `lomboksecurity`; fitur `std` (bawaan); `json.rs` adalah parser dan serializer JSON internal yang keluarannya setara `JSON.stringify`; `tests/` dikecualikan dari paket crates.io karena membaca `../vectors` |
| `typescript/` | `src/security.ts` (fungsi kontrak dan `call`), `src/crypto.ts` (SHA-1, SHA-256, HMAC, PBKDF2, base64, hex, UTF-8), `src/index.ts`; `test/` dikompilasi ke `dist-test/` |

## 5. Catatan

`LICENSE-*` di `rust/` adalah salinan dari root agar ikut paket crate. `typescript/` menyalin README dan LICENSE saat `npm pack` (skrip `prepack`/`postpack`). Fungsi `call(fn, args)` di port Rust adalah titik masuk dinamis yang dipakai runner vector dan host FFI.
