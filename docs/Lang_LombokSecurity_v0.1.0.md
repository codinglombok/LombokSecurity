# Lang LombokSecurity v0.1.0

## 1. i18n level

Level **E** (error messages and documentation only). The library produces no end-user text other than error messages; the password violation codes (`too_short` and so on) are translated by the application. The source language of all messages and documentation is English.

## 2. Message ID catalog (normative)

Format `lomboksecurity.<kind>.<code>`. Catalog files: `locales/<bcp47>/lomboksecurity.json`, one file for all ports.

| ID | Source text (en) | Error code |
|---|---|---|
| `lomboksecurity.error.invalid_secret` | The secret must be at least 16 bytes. | `invalid_secret` |
| `lomboksecurity.error.invalid_nonce` | The nonce must be 32 lowercase hexadecimal digits. | `invalid_nonce` |
| `lomboksecurity.error.invalid_header` | A header name or value is invalid. | `invalid_header` |
| `lomboksecurity.error.invalid_csp` | A Content Security Policy directive or source is invalid. | `invalid_csp` |
| `lomboksecurity.error.invalid_option` | An option or configuration value is invalid. | `invalid_option` |
| `lomboksecurity.error.invalid_input` | An argument has the wrong type or encoding. | `invalid_input` |

An error carries `code` (contract, the same in all ports) and `messageId`. The `message` field of the error object is in English and is not normative.

## 3. Current coverage

Core-20: 2 of 20 (`en`, `id`). Nusantara pack: 0 of 6. No other languages yet. Catalogs for additional languages must be reviewed by a native speaker before they are accepted.

## 4. How to add a language

1. Copy `locales/en/lomboksecurity.json` to `locales/<bcp47>/lomboksecurity.json`.
2. Translate the values; keys are not changed.
3. Ask a native speaker to review, then open a pull request.

## 5. Dependency on LombokLocale

None in 0.1.0. A consumer that uses LombokLocale can resolve `messageId` against the catalogs above.
