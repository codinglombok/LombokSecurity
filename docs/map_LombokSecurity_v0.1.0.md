# Map LombokSecurity v0.1.0

## 1. Dependency position

L0. The cluster position and catalog number follow the ecosystem parent document v3.6 (not committed, ADR-024). No required Lombok dependencies.

## 2. Example dependents in the ecosystem

This section is the only place where application or framework names may appear (ADR-019). It is an illustration, not ownership; anyone can use LombokSecurity.

| Dependent | Kind | Integration status | Notes |
|---|---|---|---|
| LombokClarion v3 | Framework | planned (F7) | Replaces the CSRF, security-header and rate-limit logic of the internal v2 security package |
| LombokAuth | Library | planned (optional) | Password policy at registration |
| LombokServer | L4 library | planned | Security headers and rate limiting |
| LombokDocFlow | Application | planned | Safe redirects and CSRF |

Optional integration with LombokCache (rate limiter state storage) and LombokLog (audit trail of violations) is not implemented.

## 3. Depends on

Nothing.

## 4. Normative contract path

`docs/SPEC_LombokSecurity_v0.1.0.md` -> `vectors/lomboksecurity-vectors-v1.json` (sha256 in SPEC) -> runners `rust/tests/vectors.rs` and `typescript/test/vectors.test.ts`.

## 5. Folder map

See `structure_repo_LombokSecurity_v0.1.0.md`.
