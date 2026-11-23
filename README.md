# Private Vault Backend

## Quick Operations Reference

See [OPERATIONS.md](OPERATIONS.md) for common commands, paths, reinstallation, and backup recovery. When changing operational commands, paths, installation, authentication, backups, networking, or limits, update that guide in the same change. Public documentation must use example deployment values; keep real host details in ignored `OPERATIONS.local.md` and `.env.pi`.


Rust API for a single-user, private-network password manager. The server stores encrypted vault envelopes and entries. Master-password processing, encryption/decryption, and password generation belong to the future client. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Implementation Status

Implemented in source: WebAuthn enrollment/login, credential management, hashed in-memory sessions, CSRF/origin checks, owner-scoped encrypted CRUD, revision conflicts, deletion tombstones, transactional audit events, local account recovery, migrations, and independent snapshot/checkpoint tooling.

**Verified with the patched dependency graph and Rust 1.100:** formatting, Clippy with warnings denied, all 27 Rust test executions (including the subprocess fixture entry point), all 27 Python tests, the optimized release build, source-integrity checks, and Compose static validation pass. The otherwise-disabled MySQL adapter compiles when explicitly enabled for verification. The patched release binary also passed migration, enrollment/recovery, owner-only permission, hashed enrollment-token, audit persistence, database integrity, and exclusive-lock smoke checks.

**Audit:** `Cargo.lock` resolves patched `libsqlite3-sys` 0.39.1 and stable RSA 0.10.0. The cached RustSec audit reports **zero vulnerabilities**, with the unused optional chrono maintenance warning still visible and no advisory exclusions. See [vendor/README.md](vendor/README.md) for the compatibility patches, provenance, and maintenance requirements. Refreshing advisories and checking yanked status still need network access.

**Container validation passed on November 17, 2026:** the user-run isolated Docker test completed all ten checks, including image builds, non-root startup, trusted HTTPS, authentication/origin rejection, hardening, permissions, snapshots, and persistent-database reopening after restart. Cleanup succeeded. Exact image digests and results are recorded in `.validation/containers-latest.json`.

**Encrypted recovery verified on November 17, 2026:** the user-run disaster-recovery drill passed all 18 checks with age 1.3.2, and cleanup succeeded. After removing the original disposable API container, source volume, and plaintext snapshot, it recovered the encrypted vault state into a fresh volume using the age-encrypted backup, recovery identity, and independent checkpoint. Incorrect keys, corrupted/truncated backups, mismatched checkpoints, and altered restored state were rejected. HTTPS and authentication checks passed after recovery. The report is `.validation/recovery-latest.json`; operational/security exercises below remain pending. No frontend or password-generation endpoint is included.

## Local Development

Install current stable Rust (dependencies require at least Rust 1.89), a C toolchain for SQLite, and Python 3.11+. Install `age` and `age-keygen` (on macOS: `brew install age`) for the encrypted recovery tests. Then:

```sh
cargo fetch --locked
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s tests -p 'test_*.py' -v
cargo build --locked --release
cargo run --locked -- migrate
cargo run --locked -- init --token-file data/enrollment.token
```

`migrate` creates the owner-only `data/` directory and database. Enrollment tokens expire after ten minutes and are stored hashed in SQLite. The token file must be new, stays local, and should be removed after enrollment. If enrollment expires, stop the server and run `recover` with a new token file.

Set configuration before serving:

```sh
export VAULT_ORIGIN=https://vault.home.arpa
export VAULT_RP_ID=vault.home.arpa
export VAULT_BIND=127.0.0.1:8080
cargo run --locked -- serve
```

Run behind a trusted HTTPS reverse proxy preserving Host. Point private DNS to the host and trust its certificate authority on your devices. Plain HTTP access cannot use Secure cookies and is unsupported. Startup rejects wildcard/public bind addresses, insecure origins, and missing/changed migrations. A process lock prevents simultaneous serving and maintenance against the same database.

## API Contract

All paths except `/health` use `/api/v1`. Bodies are JSON; binary fields use canonical URL-safe base64 without padding. Mutation requests require the exact configured `Origin`. Authenticated mutations also require `X-CSRF-Token`; obtain it from the login response or `GET /auth/session`.

| Method / path | Purpose |
| --- | --- |
| `POST /auth/bootstrap/begin` | Begin initial/recovery enrollment with `{"enrollment_token":"…"}`. |
| `POST /auth/bootstrap/finish` | Submit the WebAuthn registration response. |
| `POST /auth/login/begin`, `/auth/login/finish` | Challenge and assertion; finish sets the session cookie. |
| `GET /auth/session`, `POST /auth/logout` | Inspect or revoke the session. |
| `GET /auth/credentials` | List enrolled credential identifiers. |
| `POST /auth/register/begin`, `/auth/register/finish` | Add an authenticator using a fresh authenticated session. |
| `DELETE /auth/credentials/{id}` | Remove a credential; requires fresh authentication, preserves the last credential, revokes all sessions. |
| `GET`, `PUT`, `DELETE /vault` | Retrieve, create/update, or permanently tombstone the vault. Mutations require fresh authentication. |
| `GET /entries?after={uuid}&limit=100` | Page entries, including tombstones, in identifier order. |
| `GET`, `PUT`, `DELETE /entries/{uuid}` | Read, create/update, or tombstone an encrypted entry. |

WebAuthn begin responses contain `options` and set a short-lived ceremony cookie. Finish requests must return that cookie with the complete authenticator response. One browser ceremony at a time is supported. Challenges are single-use, including failed verification. Enroll a second authenticator after logging in. A fresh session is at most five minutes old; reauthenticate through login to refresh it.

Create a vault using a client-generated UUID, `expected_revision: 0`, and an `envelope`:

```json
{
  "version": 1,
  "salt": "<16 bytes, base64url>",
  "nonce": "<24 bytes, base64url>",
  "wrapped_key": "<48 bytes, base64url>",
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1
  }
}
```

Allowed memory profiles are 65536, 131072, and 262144 KiB. The backend validates the format; it cannot authenticate ciphertext without the client key. Entry PUT bodies contain `expected_revision`, `ciphertext` (16–65536 decoded bytes), and `nonce` (24 decoded bytes). DELETE bodies contain `expected_revision`. Use the returned revision for subsequent writes; a stale revision returns 409. Vault `sequence` tracks all vault mutations, while vault `revision` tracks envelope changes/deletion. Paginated reads are not a consistent synchronization snapshot; clients must recheck the vault sequence and repeat if it changes.

Unknown fields are rejected in vault payloads. Initial bounds: 256 KiB requests, 100 entries per page, 10000 entries including tombstones, 64 MiB encoded entry content, 32 active API requests, two reserved health requests, 32 sessions/ceremonies, 240 requests/minute, and 20 authentication operations/minute. The global rate limits are intentional for one user. Entry tombstones cannot be resurrected; deleting the whole vault is terminal in this initial version. Backups may still contain deleted ciphertext.

## Containers

Copy `.env.example` to `.env`, set the private hostname/interface, and supply reviewed digest-pinned images for Rust on Debian bookworm, Debian bookworm-slim, and Caddy. Use the checked-in `Cargo.lock`. Ensure the chosen subnet does not overlap your LAN/VPN. The Compose configuration passed isolated Docker runtime validation; configure and verify your actual host networking, firewall, DNS, and certificate trust before LAN deployment.

The API and Caddy images initialize their data directories as UID/GID 10001 with mode 0700, so fresh named volumes acquire the correct ownership without a privileged runtime initializer. Existing volumes retain their existing permissions; preserve their data before any administrative ownership repair. Then:

```sh
docker compose build api
docker compose run --rm api migrate
docker compose run --rm api init --token-file /data/enrollment.token
docker compose up -d
```

Only the private-interface HTTPS port is published. Enforce LAN/VPN source restrictions in the host firewall, including Docker forwarding rules. Caddy uses an internal CA; distribute its root certificate through a trusted channel. No public ingress or external certificate service is required.

## Independent Backups and Monitoring

Use a **separate host and administrative account** with Python 3.11+, OpenSSH, and the `age` CLI. Its SSH key must invoke only a forced snapshot command on the application host, with forwarding and PTY disabled. For containers, that command can execute `python3 /app/scripts/snapshot.py /data/vault.sqlite` through `docker compose exec -T api`; do not give the SSH account unrestricted Docker access. Neither the collector private key nor backup deletion credentials belong on the application host.

Run on the collector host, for example every five minutes:

```sh
python3 scripts/collect.py --archive /srv/vault-backups --recipient age1YOUR_PUBLIC_RECIPIENT -- ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes vault-snapshot
python3 scripts/check_checkpoint.py /srv/vault-backups --max-age 900
```

Configure your scheduler/monitor to alert on either nonzero exit status. Schedule the freshness check independently, so collector failure cannot suppress it. Use a known SSH host key and external retention/immutability controls. The tool creates new encrypted snapshots and protected audit/checkpoint files, never deletes retained versions, and rejects sequence regressions or changed/missing previously observed events. Initial collection establishes a trusted baseline; review it locally.

This release retains the full audit outbox and fails writes at 100000 events. Archived events are pulled with snapshots rather than pushed by a background worker. Outbox pruning and automated retention require a later acknowledged-archive design; monitor growth before reaching the limit.

To restore, stop the server, decrypt the selected backup using an offline recovery identity, and copy its matching checkpoint from the independent archive. Validate before touching the live database:

```sh
age --decrypt --identity /secure/offline-identity.txt --output /secure/restore.sqlite /srv/vault-backups/SELECTED.sqlite.age
python3 scripts/verify_restore.py /secure/restore.sqlite /secure/SELECTED.checkpoint.json
```

Compare the chosen checkpoint with the collector's latest checkpoint. An older recovery point requires an explicit operator decision recorded externally. Preserve the existing database and WAL/SHM files separately; install the verified database in a clean private directory with owner-only permissions. Never combine a restored database with old WAL/SHM files. Validate migrations and restart; sessions/challenges cannot survive because they are only in process memory. Use `recover --token-file ...` while stopped if account credentials also need replacement. Record the recovery event in your independent monitoring system before reopening access.

## Verification

Rust tests cover WebAuthn enrollment/login/replay/origin checks, session expiry/revocation, CSRF, authorization, invalid input, revision races, atomic audit failure, and payload limits. Python tests exercise actual SQLite WAL snapshots, checkpoint tampering/regression, transport limits, and foreign-key ownership constraints. The GitHub workflow supplies formatting, linting, a release build, tests, and dependency advisory checks when this repository is pushed. The workflow itself has not run here; the local checks listed above have run.

Remaining release work includes actual `age` encryption/restore round trips, real-authenticator testing, operational monitoring integration, disk-full/crash/load exercises, image/dependency review, and independent security review. Backend controls cannot validate future client cryptography or prevent a fully compromised host from serving dishonest responses; independent checkpoints provide bounded detection and recovery.

## Dependency Security Status

The local compatibility backports preserve the backend architecture and delegate cryptographic operations to the patched upstream RSA library. Cargo—not manual lockfile editing—resolved the updated graph:

- `libsqlite3-sys` **0.39.1**, bundling SQLite 3.54.1, addresses [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459). Only the SQLx SQLite driver's dependency constraint changes; its driver source is unchanged.
- RSA **0.10.0** addresses [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071). The crypto-glue patch preserves WebAuthn RS256 compatibility using the stable feature/key names. The disabled MySQL driver's adapter is also updated so RSA 0.9 is no longer retained in Cargo.lock. That does not enable MySQL for this application.
- Chrono 0.4.45 remains an unused optional dependency in SQLx's lockfile resolution, with an unmaintained warning and no patched upgrade. The warning is neither excluded nor represented as fixed. Reassess it before enabling any additional SQLx features.

`cargo audit --no-fetch --no-yanked` currently reports zero vulnerabilities against the cached database of 1527 advisories. Refreshing that database and checking yanked status still need network access. This scan checks package versions; the updated graph has also passed the build and tests listed above. Deployment verification remains separate. The independent Python backup tools use their Python runtime's SQLite library, which is separate from the bundled Rust driver.

The reviewed-source hashes, original archive checksums, minimal diffs, licenses, and removal conditions are in [vendor/README.md](vendor/README.md). CI verifies vendored files and separately compiles the disabled MySQL adapter. There are no advisory exclusions.

## Isolated Container Validation

Run from a terminal that can access the Docker daemon:

```sh
python3 scripts/validate_containers.py
```

This pulls official Rust, Debian, and Caddy images, resolves their exact registry digests, and builds both images. Optional `--rust-image`, `--runtime-image`, and `--caddy-image` arguments accept previously reviewed digest-pinned references instead of the default tags. Pulling and pinning an image does not constitute a vulnerability review of that image.

The script uses a random Compose project, fresh disposable volumes, an unused loopback port, and a subnet that does not overlap existing Docker networks. It never uses the normal project's volumes or enrollment. It validates non-root migrations/provisioning, Caddy configuration, HTTPS with certificate/hostname verification, anonymous-access and origin rejection, container hardening, database permissions, snapshots, and restart persistence. It removes only its own project and volumes on completion, including test failures. Interruptions that prevent Python cleanup may leave the named validation project for manual cleanup.

Results, completed checks, and exact image digests are written to `.validation/containers-latest.json`. Review this report before describing deployment as validated. The user-run live validation completed all ten checks successfully on November 17, 2026, and cleanup succeeded; the agent inspected the resulting report. Rerun after changes to images or deployment configuration. The test does not validate production firewall/VPN rules, real-authenticator enrollment, resource exhaustion, or image vulnerability findings. Check LAN/VPN routes for subnet overlap separately before deploying.

The proxy joins a normal edge bridge for published HTTPS and the internal backend bridge for API access. The API joins only the internal bridge. Validation failures save container state, port mappings, bounded startup logs, and an internal TCP probe before cleanup. Dockerfile default base references are pinned to the image digests from the first validation run; Compose still requires explicitly configured images.

## Encrypted Backup Disaster-Recovery Drill

Run from a Docker-enabled terminal with `age` and `age-keygen` installed:

```sh
python3 scripts/validate_containers.py --recovery
```

This extends the isolated container validation using only disposable resources. It seeds opaque synthetic vault records, a live entry, revisions, and a deletion tombstone; no real passwords or authenticator credentials are used. The actual collector code encrypts a consistent snapshot for a temporary recovery identity and saves the independent checkpoint. Negative checks cover an incorrect identity, modified/truncated ciphertext, modified restored state, and a mismatched checkpoint.

The drill then stops and removes its original API container, verifies the source volume's project labels, deletes only that disposable source volume, and removes the original plaintext snapshot. It decrypts the saved backup, verifies the exact file and checkpoint, installs it in a different empty named volume, and starts a fresh API container. The restored live snapshot must preserve the complete canonical state, including ciphertext, wrapped-key envelope, revisions, tombstones, account metadata, and audit history. HTTPS and unauthenticated-access checks run again.

The November 17, 2026 user-run drill passed all 18 checks, including source-volume removal and fresh-volume recovery; the agent inspected the report. Results go to `.validation/recovery-latest.json` as well as the container validation report. Disposable keys and plaintext candidates are removed with the temporary directory; neither keys nor record payloads are included in reports. Failure diagnostics are captured before cleanup. Local deletion is cleanup, not a guarantee of forensic erasure.

This verifies recovery of the backend's encrypted vault data. The future client still needs its vault master password or a separately designed vault recovery mechanism to decrypt entries. The drill does not enroll or exercise a real authenticator, prove session revocation with an existing browser session, or physically separate the collector/key hosts. For production, keep the private recovery identity offline and retain trusted checkpoints independently of the application host.

## Failure and Load Verification

Run the focused fault-injection suite with:

```sh
cargo test --locked --test resilience
```

The local suite passes with real SQLite errors and temporary databases: `SQLITE_FULL` using a page-count limit, read-only storage, writer-lock contention, exhausted audit capacity, cancellation with a live transaction, the ten-second request deadline, 64-way revision races, rate exhaustion, and API saturation. It checks unchanged revisions/audit state after failed writes, successful writes after recoverable faults, database integrity, and continued authorization. A subprocess commits one entry, spills more than 1 MiB of uncommitted WAL, and is forcibly killed; reopening preserves only the commit and can accept new writes. The fixture entry-point test is called by that subprocess and is not an independent test scenario.

These tests identified and fixed two behaviors: unavailable SQLite storage now returns a generic 503 without exposing database messages, and `/health` has two reserved request slots independent of the 32 API slots. Health is process liveness, not a declaration that storage is writable.

For the disposable Docker/HTTPS drill, run:

```sh
python3 scripts/validate_containers.py --resilience
```

Add `--recovery` to combine it with the encrypted recovery drill, as CI does. The load phase sends 300 anonymous protected-endpoint requests with concurrency 16 while checking health, requires throttling and no successful access, checks origin rejection, and compares complete persistent state before/after. It then SIGKILLs only its disposable API container and verifies restart, authentication, and unchanged committed data. It does not test authenticated HTTPS writes; those races are exercised through the Rust API/router tests.

Results and observed request latency percentiles go to `.validation/resilience-latest.json`; they are observations for the test machine, not a production throughput guarantee. The November 17, 2026 user-run combined drill passed all 21 checks and cleanup succeeded. Of 300 anonymous requests at concurrency 16, 239 returned 401 and 61 returned 429; none gained access. Health stayed reachable, state was unchanged after overload and SIGKILL/restart, and encrypted recovery passed. The observed p95 request time was 11.9 ms for this particular anonymous-request sample; this does not measure authenticated vault throughput. The agent inspected `.validation/resilience-latest.json`. The local suite does not fill the host disk, simulate power loss or hardware failure, or prove performance during a sustained distributed attack. Reserve health capacity in the API cannot guarantee responsiveness if the host or reverse proxy itself is exhausted.

## Raspberry Pi Staging

For the ARM64 Raspberry Pi 4 running Debian 13, see [deploy/raspberry-pi.md](deploy/raspberry-pi.md). The optional Pi overlay uses workstation-built ARM64 images and starts with loopback-only HTTPS. It preserves the standard container hardening and database volumes. The user has verified the running Pi backend over HTTPS from the Mac at `https://vault.home.arpa/health`. The scoped firewall is applied, and a disposable Docker bridge client was blocked with three packets counted by the DROP rule. The firewall unit is enabled/active and Docker's loaded Requires/After ordering is verified. Actual reboot persistence remains untested.

The Pi LAN firewall profile and its systemd startup dependency are documented in [deploy/raspberry-pi.md](deploy/raspberry-pi.md). Shell/state-model tests and the user-run LAN allow/drop checks pass; reboot verification remains pending.

## Mac Backup Collection

See [deploy/mac-backups.md](deploy/mac-backups.md) for hourly encrypted pulls, a restricted Pi SSH export account, pinned host keys, and checks for backups older than 24 hours. Scheduling requires a successful manual collection first. All 38 Python tests pass locally, including 11 collector setup and monitoring tests. Live SSH export, launchd execution, and notification delivery remain unverified until device installation. A sleeping or offline Mac does not provide continuous monitoring.

## Browser Client (Initial Implementation)

See [client/README.md](client/README.md) for passkey sign-in, client-side Argon2id/XChaCha20-Poly1305 vault encryption, build instructions, trust boundaries, and browser acceptance checks. Build `client/dist/` before building the proxy image. The live Pi is unchanged until rebuilt images are transferred. All eight client tests pass, including real Argon2id/XChaCha encryption, tampering rejection, and browser-distribution initialization; the static build also passes. Live browser/passkey acceptance checks and updated container validation remain pending. The user-run online npm advisory scan reported zero vulnerabilities; updated container validation remains pending after the asset-permission fix.
