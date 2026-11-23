# Private Vault Client

Hostnames and paths in this public guide are examples; use your private deployment configuration.

An initial browser client for the existing single-owner backend. It supports passkey enrollment/login, another passkey registration, vault initialization/unlock, encrypted entry creation/editing/deletion, and a cryptographically random 24-character password generator. No frontend framework, external CDN, analytics, service worker, localStorage, or IndexedDB is used.

## Build and test

Use Node.js 20 or newer (Node 24 is recommended):

```sh
cd client
npm install --ignore-scripts  # first checkout: create and review package-lock.json
npm audit --audit-level=low
npm test
npm run build
```

Once the lockfile exists, use `npm ci --ignore-scripts` for subsequent installs and CI. Commit the lockfile. The only direct dependency is exactly pinned `libsodium-wrappers-sumo`; its sumo build provides Argon2id. Build copies the package's UMD distributions into `dist/vendor/`; no remote requests happen at browser runtime. Do not substitute a CDN.

Build before building the proxy container: its Dockerfile copies `client/dist/`. CI tests/builds the client before container validation. The browser is served by Caddy on the same origin as `/api/*`; backend routes and their security headers remain separate. Never serve the client from an unrelated development origin or relax backend origin checks. Rebuild and transfer the ARM64 proxy image using the existing Pi procedure. This source change does not update the running Pi automatically.

## Encryption format and boundaries

The master password is independent of the login passkey. Argon2id v1.3 derives a 32-byte wrapping key with a random 16-byte salt, 64 MiB memory, three iterations, and parallelism one. A random 32-byte vault key is wrapped with XChaCha20-Poly1305 and a random 24-byte nonce. The envelope matches backend version 1. Existing allowlisted 128/256 MiB envelopes are also accepted; arbitrary parameters are rejected before deriving a key.

Wrapped-key associated data is UTF-8 JSON of `["private-vault",1,"key",owner,vault,kdf,salt]`, with KDF keys ordered `algorithm,version,memory_kib,iterations,parallelism`. Entry associated data is UTF-8 JSON of `["private-vault",1,"entry",owner,vault,entry,nextRevision]`. UUIDs use canonical lowercase strings. All binary API fields are canonical unpadded base64url. Entries contain exactly title, username, password, URL, and notes, encrypted together. Fresh random nonces are generated for every encryption; ciphertext includes the authentication tag. Revision conflicts never silently overwrite records or trigger blind retries.

The dedicated worker retains the key; it does not return it to the UI. It wipes byte buffers where feasible. Locking terminates the worker and clears UI entries and editor fields. It locks after five minutes of unlock time, on tab hiding, and on page exit. JavaScript strings, browser snapshots, OS memory, and previously displayed plaintext cannot be reliably erased. Rendering uses DOM text and form values, never HTML interpolation from entries. Nothing automatically opens stored URLs or copies secrets to a clipboard.

This protects stored vault content against a database-only disclosure and detects ciphertext/context tampering. A compromised browser, extension, operating system, or server that delivers malicious client code can steal unlocked data/master passwords. CSP and worker isolation do not remove that trust boundary. Full-state rollback/deletion is not prevented by AEAD; independent checkpoints and backups remain necessary. Login alone does not decrypt the vault, and neither an administrator nor the age backup identity can recover entries without the master password. There is no master-password reset or migration of synthetic test envelopes.

## First browser validation

Trust the Pi's public Caddy root CA in the browser/OS after verifying its identity, and open `https://vault.home.arpa/` without certificate errors. Use the existing administrator account-provisioning procedure to obtain a short-lived enrollment token; enter it only in the enrollment form. Tokens never go in URLs. Enroll a real passkey, sign in, then create a vault using a unique master password of at least 16 characters. Start with synthetic entries.

Verify enroll/login, wrong-password rejection, creation/edit/deletion, lock and unlock, tab-hide lock, a second browser's revision conflict, reload/login after API restart, and another passkey. Check developer tools for plaintext-free API payloads, absence of persistent browser storage, and CSP/worker errors. Run the disposable container validation after the build. The eight local client tests and static build pass, including real-crypto negative cases and UMD loading in a simulated browser global context. This simulation is not a real browser test. The user-run online npm audit found zero vulnerabilities. The updated container drill must also pass before deployment. This first implementation has not yet undergone real-browser/passkey acceptance testing or an independent security review; do not use real passwords until the acceptance checks pass.

Crypto references: [libsodium.js](https://github.com/jedisct1/libsodium.js), [Argon2id API](https://doc.libsodium.org/password_hashing/default_phf), and [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
