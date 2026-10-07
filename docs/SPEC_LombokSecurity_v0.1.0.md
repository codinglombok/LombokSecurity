# SPEC LombokSecurity v0.1.0

This document is the normative cross-language contract. Every language port MUST produce byte-identical output for all specified inputs. Deviations from this specification are bugs.

Key words MUST, MUST NOT, SHOULD and MAY are interpreted as in RFC 2119 and RFC 8174.

| Atribut | Nilai |
|---|---|
| Versi kontrak | 0.1.0 |
| Tanggal tinjauan standar acuan | 2026-10-07 |
| Vector | `vectors/lomboksecurity-vectors-v1.json` |
| SHA-256 vector | `bc39de3f3d6de49dc8e90d0bde1ff0ff571d2160477a58b4f83720f31ff9693f` |

## 0. Standar acuan (U2)

| Acuan | Versi | Pemakaian |
|---|---|---|
| FIPS 180-4 | Agustus 2015 | SHA-256 (dan SHA-1 internal) |
| RFC 2104, RFC 4231 | 1997, 2005 | HMAC dan vector uji HMAC-SHA256 |
| RFC 3629 | 2003 | Encoding UTF-8 string masukan |
| RFC 9110 | Juni 2022 | Sintaks `token` untuk nama header |
| Content Security Policy Level 3 | W3C Working Draft 2024 | Serialisasi direktif |
| NIST SP 800-63B | Revisi 3 | Dasar kebijakan kata sandi bawaan (panjang dan daftar blokir) |
| RFC 6585 | 2012 | Status 429 dan makna `retryAfter` |
| RFC 2119, RFC 8174 | 1997, 2017 | Kata kunci normatif |

## 1. Vector

Berkas vector memuat `{ format, specVersion, note, groups }`. Setiap kasus memuat `name`, `fn`, `args`, `expect` (`{ "result": ... }` atau `{ "error": code }`). Dalam `args`, objek `{ "hex": "..." }` berarti byte; string berarti byte UTF-8-nya. Setiap port yang diklaim MUST menjalankan seluruh kasus lewat titik masuk `call(fn, args)` dan menghasilkan hasil yang sama persis. Hash SHA-256 berkas MUST sama dengan tabel atribut.

## 2. Hashing

`sha256Hex(data)` dan `hmacSha256Hex(key, data)` menghasilkan heksadesimal huruf kecil. `timingSafeEqual(a, b)` bernilai true bila kedua urutan byte sama; durasinya MUST hanya bergantung pada panjang. Argumen yang bukan string atau byte, atau `{hex}` yang tidak sah (panjang ganjil, karakter non-heksadesimal), MUST `invalid_input`.

## 3. CSRF

`secret` adalah byte (string: UTF-8) dengan panjang paling sedikit 16 (selain itu `invalid_secret`). `nonce` MUST tepat 32 digit heksadesimal huruf kecil (`invalid_nonce`). `context` opsional MUST string (`invalid_input`); tidak ada atau null setara string kosong.

`createCsrfToken(secret, nonce, context?)` = `nonce + "." + hex(HMAC-SHA256(secret, "csrf|" + nonce + "|" + context))`. Urutan validasi: secret, nonce, context.

`verifyCsrfToken(secret, token, context?)`: setelah memvalidasi secret dan context, token yang bukan string bernilai false. Token dipecah pada `.` pertama; bagian kiri MUST cocok aturan nonce dan bagian kanan MUST tepat 64 digit heksadesimal huruf kecil, selain itu false. Hasil adalah perbandingan waktu-konstan antara tanda tangan yang dihitung dan bagian kanan. Fungsi ini MUST tidak melempar untuk token apa pun.

## 4. Header keamanan

Header bawaan, berurutan:

| Nama | Nilai |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

`securityHeaders(overrides?)`: `overrides` tidak ada atau null berarti bawaan; selain objek MUST `invalid_option`. Setiap kunci diproses menurut urutan properti (ECMA-262): nama MUST token RFC 9110 (`invalid_header`); nilai MUST null atau string tanpa U+0000..U+0008, U+000A..U+001F, U+007F (tab diizinkan; selain itu `invalid_header`). Bila nama sama (tanpa membedakan huruf besar-kecil ASCII) dengan entri yang ada, nilainya diganti di posisinya dan ejaan nama entri itu dipertahankan; selain itu entri ditambahkan di akhir. Entri bernilai null dihapus dari hasil. Hasil adalah array pasangan `[nama, nilai]`.

## 5. CSP

`buildCsp(directives)`: objek (selain itu `invalid_csp`). Setiap direktif menurut urutan properti: nama MUST cocok `^[a-z][a-z0-9-]*$`; nilai `true` menghasilkan nama saja; nilai array berisi sumber, masing-masing string tidak kosong tanpa karakter U+0000..U+0020, U+007F, `;`, `,`; array kosong menghasilkan nama saja; nilai lain MUST `invalid_csp`. Direktif dirangkai `nama + " " + sumber.join(" ")` dan digabung dengan `"; "`. Objek kosong menghasilkan string kosong.

## 6. Escape HTML

`escapeHtml(text)`: `&` menjadi `&amp;`, `<` menjadi `&lt;`, `>` menjadi `&gt;`, `"` menjadi `&quot;`, `'` menjadi `&#39;`; karakter lain apa adanya. Bukan string: `invalid_input`.

## 7. Redirect aman

Opsi: `allowedHosts` (array string tidak kosong) dan `fallback` (jalur lokal, bawaan `/`). Kunci lain atau bentuk salah MUST `invalid_option`; opsi divalidasi sebelum target.

Karakter tidak aman: U+0000..U+0020, U+007F, dan `\`. **Jalur lokal**: diawali `/`, tidak diawali `//`, tanpa karakter tidak aman.

`safeRedirect(target, options?)` mengembalikan `fallback` kecuali:

1. `target` adalah jalur lokal: dikembalikan apa adanya.
2. `target` tanpa karakter tidak aman, diawali `http://` atau `https://` (tanpa membedakan huruf besar-kecil ASCII), dengan authority (teks setelah `://` sampai `/`, `?`, `#`, atau akhir) yang tidak kosong dan tanpa `@`. Host adalah `[...]` sampai `]` pertama bila authority diawali `[`, selain itu teks sebelum `:` pertama; sisa authority MUST kosong atau `:` diikuti 1 sampai 5 digit. Bila host (huruf kecil ASCII) sama dengan salah satu `allowedHosts` (huruf kecil ASCII), `target` dikembalikan apa adanya.

Target yang bukan string atau kosong menghasilkan `fallback`.

## 8. Kebijakan kata sandi

Kebijakan (semua opsional): `minLength` (bawaan 12, paling kecil 1), `maxLength` (128, paling kecil 1), `requireLowercase`, `requireUppercase`, `requireDigit`, `requireSymbol` (bawaan false), `maxRepeat` (bawaan 0 = mati), `blocklist` (bawaan true), `extraBlocklist`, `userInputs` (array string). Kunci tak dikenal, tipe salah, atau `minLength > maxLength` MUST `invalid_option`; kebijakan divalidasi sebelum kata sandi; kata sandi bukan string MUST `invalid_input`.

`checkPassword` mengembalikan kode pelanggaran dalam urutan berikut (panjang dihitung per code point; kelas karakter hanya ASCII):

| Kode | Kondisi |
|---|---|
| `too_short` | panjang < `minLength` |
| `too_long` | panjang > `maxLength` |
| `missing_lowercase` | diminta dan tidak ada `a`-`z` |
| `missing_uppercase` | diminta dan tidak ada `A`-`Z` |
| `missing_digit` | diminta dan tidak ada `0`-`9` |
| `missing_symbol` | diminta dan tidak ada U+0021..U+002F, U+003A..U+0040, U+005B..U+0060, U+007B..U+007E |
| `repeated_characters` | `maxRepeat > 0` dan ada deret code point identik lebih panjang dari `maxRepeat` |
| `common_password` | huruf kecil ASCII kata sandi sama dengan entri daftar bawaan (bila `blocklist`) atau entri `extraBlocklist` yang dikecilkan |
| `contains_user_input` | huruf kecil ASCII kata sandi memuat huruf kecil ASCII salah satu `userInputs` yang panjangnya paling sedikit 3 code point |

Daftar bawaan adalah 40 entri `COMMON_PASSWORDS` yang identik di semua port.

## 9. Rate limiting

Semua nilai konfigurasi MUST bilangan bulat 1..2^53-1 dan waktu bilangan bulat 0..2^53-1 (`invalid_option`). Status dipasok dan dikembalikan pemanggil.

**Fixed window** (`limit`, `windowMs`): `windowStart = now - now mod windowMs`. Hitungan adalah hitungan status bila `windowStart` status sama, selain itu 0. Diizinkan bila hitungan < `limit` (lalu hitungan + 1). `remaining = max(0, limit - hitungan)`. `retryAfter` 0 bila diizinkan, selain itu `windowStart + windowMs - now`.

**Token bucket** (`capacity`, `refillTokens`, `refillIntervalMs`, `cost` bawaan 1, `cost <= capacity`): tanpa status, token = `capacity` dan `updatedAt = now`. Bila `now > updatedAt`: `k = floor((now - updatedAt) / refillIntervalMs)`, token = `min(capacity, token + k * refillTokens)`, lalu `updatedAt = now` bila token penuh, selain itu `updatedAt + k * refillIntervalMs`. Diizinkan bila token >= `cost` (token dikurangi `cost`; `retryAfter` 0). Bila tidak: `retryAfter = ceil((cost - token) / refillTokens) * refillIntervalMs - max(0, now - updatedAt)`. `remaining` adalah token setelah keputusan.

`simulateRateLimit(kind, config, times)`: `kind` adalah `fixedWindow` atau `tokenBucket`, `times` array; menjalankan limiter berurutan dan mengembalikan `{ allowed, remaining, retryAfter }` per waktu. Konfigurasi divalidasi pada setiap langkah sebelum waktu.

## 10. Keamanan

- Perbandingan tanda tangan MUST waktu-konstan; `verifyCsrfToken` MUST tidak membocorkan alasan penolakan.
- Header dan CSP MUST tidak dapat memuat pemisah baris atau pemisah direktif yang disisipkan.
- `safeRedirect` MUST tidak pernah mengembalikan target yang membawa ke host di luar `allowedHosts`.
- Masukan apa pun MUST menghasilkan hasil atau galat dengan `code` pada bagian 11; panic atau pengecualian lain adalah bug.

## 11. Galat

| `code` | Kondisi | `messageId` |
|---|---|---|
| `invalid_secret` | secret kurang dari 16 byte | `lomboksecurity.error.invalid_secret` |
| `invalid_nonce` | nonce tidak sah | `lomboksecurity.error.invalid_nonce` |
| `invalid_header` | nama atau nilai header tidak sah | `lomboksecurity.error.invalid_header` |
| `invalid_csp` | direktif atau sumber CSP tidak sah | `lomboksecurity.error.invalid_csp` |
| `invalid_option` | opsi, kebijakan, atau konfigurasi tidak sah; fungsi tak dikenal | `lomboksecurity.error.invalid_option` |
| `invalid_input` | argumen bertipe atau ber-encoding salah | `lomboksecurity.error.invalid_input` |

## 12. Non-goals (0.1.0)

Enkripsi, tanda tangan asimetris, hashing kata sandi (lihat library autentikasi), CORS, sanitasi HTML penuh (whitelist tag), normalisasi IDN, dan penyimpanan status rate limiter bersama.

## 13. Riwayat perubahan kontrak

| Versi | Perubahan |
|---|---|
| 0.1.0 | Kontrak awal |
