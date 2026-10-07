# Lang LombokSecurity v0.1.0

## 1. Tingkat i18n

Tingkat **E** (pesan error dan dokumentasi saja). Library tidak menghasilkan teks untuk pengguna akhir selain pesan galat; kode pelanggaran kata sandi (`too_short`, dan seterusnya) diterjemahkan oleh aplikasi.

## 2. Katalog ID pesan (normatif)

Format `lomboksecurity.<jenis>.<kode>`. Berkas katalog: `locales/<bcp47>/lomboksecurity.json`, satu berkas untuk semua port.

| ID | Teks sumber (en) | Kode galat |
|---|---|---|
| `lomboksecurity.error.invalid_secret` | The secret must be at least 16 bytes. | `invalid_secret` |
| `lomboksecurity.error.invalid_nonce` | The nonce must be 32 lowercase hexadecimal digits. | `invalid_nonce` |
| `lomboksecurity.error.invalid_header` | A header name or value is invalid. | `invalid_header` |
| `lomboksecurity.error.invalid_csp` | A Content Security Policy directive or source is invalid. | `invalid_csp` |
| `lomboksecurity.error.invalid_option` | An option or configuration value is invalid. | `invalid_option` |
| `lomboksecurity.error.invalid_input` | An argument has the wrong type or encoding. | `invalid_input` |

Galat membawa `code` (kontrak, sama di semua port) dan `messageId`. Pesan `message` di objek galat berbahasa Inggris dan tidak bersifat normatif.

## 3. Cakupan saat ini

Core-20: 2 dari 20 (`en`, `id`). Paket Nusantara: 0 dari 6. Bahasa lain belum ada. Katalog bahasa tambahan harus ditinjau penutur asli sebelum diterima.

## 4. Cara menambah bahasa

1. Salin `locales/en/lomboksecurity.json` ke `locales/<bcp47>/lomboksecurity.json`.
2. Terjemahkan nilai; kunci tidak diubah.
3. Minta tinjauan penutur asli, lalu ajukan PR.

## 5. Ketergantungan LombokLocale

Tidak ada pada 0.1.0. Konsumen yang memakai LombokLocale dapat me-resolve `messageId` terhadap katalog di atas.
