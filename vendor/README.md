# Temporary dependency compatibility patches

These are source copies from the published crates.io archives, not replacement cryptographic implementations. `provenance.json` records the original archive SHA-256 (verified against the cached crates.io index), licenses, modified files, and hashes of the distributed files. Review the unified diffs in `patches/`. Run `python3 scripts/verify_vendor.py` to verify the checked-in copies.

| Crate | Upstream version | Local changes | Removal condition |
| --- | --- | --- | --- |
| sqlx-sqlite | 0.8.6 | Pin `libsqlite3-sys =0.39.1` (bundled SQLite 3.54.1). Driver source is unchanged. | A compatible released SQLx driver accepts patched SQLite. |
| crypto-glue | 0.2.2 | Pin stable RSA 0.10.0; replace the removed `sha2` feature with `pkcs1v15`; use the renamed, nondeprecated RSA key types. | A compatible crypto-glue release supports stable patched RSA. |
| sqlx-mysql | 0.8.6 | Pin the same patched RSA; adapt public-key parsing names and OAEP encryption to the stable API; preserve SHA-1 for the existing MySQL protocol using a digest-version alias. | SQLx no longer locks the affected RSA version or provides a compatible patched MySQL adapter. |

The MySQL driver is disabled for this application. Its patch removes RSA 0.9 from Cargo's full lockfile without manually pruning the lockfile or excluding advisories. It does not enable a MySQL backend. CI separately compiles this otherwise-disabled adapter; actual MySQL server interoperability is outside this SQLite application's supported deployment.

No RSA padding scheme, hash algorithm, randomness source guarantee, or cryptographic primitive is replaced. The OAEP adapter delegates encryption to the stable RSA API, which uses the operating-system RNG by default. The `pkcs1v15` feature preserves WebAuthn's existing RS256 signature compatibility; it is not used for vault encryption. Source changes are integration changes only.

## Verification and maintenance

1. Fetch the lockfile dependencies (`cargo fetch --locked`).
2. Run `cargo fmt --all -- --check`, Clippy, application tests, and a release build with `--locked`.
3. Run `cargo check --locked --features sqlx/mysql --lib` to compile the disabled driver patch.
4. Run `cargo test --locked --test dependency_compatibility` for RSA signing/verification, tamper rejection, OAEP round trips, SQLite runtime version, and WAL/reopen behavior. Run the full WebAuthn and backup suites as well.
5. Run `cargo audit`; do not introduce advisory exclusions. The separate chrono maintenance warning remains visible because SQLx retains an unused optional chrono dependency.

Verified locally on November 17, 2026 with Rust 1.100: all 16 Rust tests (including the targeted RSA/SQLite tests), all ten Python tests, Clippy with warnings denied, formatting, the release build, source hashes, and the explicitly enabled MySQL adapter check pass. Release CLI migration/enrollment/recovery and permission/locking smoke checks also pass. The targeted OAEP test exercises both the WebAuthn adapter's SHA-256 helper and the disabled MySQL adapter's SHA-1 API path.

The cached RustSec scan reports zero vulnerabilities, with the unused chrono maintenance warning visible. Yanked status was not checked and the advisory database was not refreshed in this restricted session. Passing these checks does not establish constant-time behavior independently of the upstream implementation or real MySQL server interoperability.

Review upstream releases before every dependency update. Remove each `[patch.crates-io]` entry and its vendored source when an upstream replacement passes the same checks. Do not independently modify cryptographic arithmetic, padding, signature validation, or SQLite's C source.

## Licenses

SQLx sources retain their MIT and Apache-2.0 license files. Crypto-glue is MPL-2.0; the standard MPL text is included as `crypto-glue/LICENSE-MPL-2.0` (copied from a cached standard MPL-2.0 license). Preserve notices and make modified covered source available under MPL-2.0 when distributing it. The exact patched source is included here. Upstream authorship and repository metadata remain in each manifest.
