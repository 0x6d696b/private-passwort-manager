CREATE TABLE accounts (
    id TEXT PRIMARY KEY NOT NULL,
    singleton INTEGER NOT NULL DEFAULT 1 UNIQUE CHECK (singleton = 1),
    enrollment_hash TEXT,
    enrollment_expires INTEGER,
    CHECK ((enrollment_hash IS NULL) = (enrollment_expires IS NULL))
) STRICT;

CREATE TABLE credentials (
    id TEXT PRIMARY KEY NOT NULL,
    owner TEXT NOT NULL REFERENCES accounts(id),
    passkey TEXT NOT NULL CHECK (length(passkey) <= 32768)
) STRICT;

CREATE TABLE vaults (
    id TEXT PRIMARY KEY NOT NULL,
    owner TEXT NOT NULL UNIQUE REFERENCES accounts(id),
    envelope TEXT NOT NULL CHECK (length(envelope) <= 4096),
    revision INTEGER NOT NULL CHECK (revision > 0),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    UNIQUE (id, owner)
) STRICT;

CREATE TABLE entries (
    id TEXT NOT NULL,
    vault TEXT NOT NULL,
    owner TEXT NOT NULL,
    ciphertext TEXT NOT NULL CHECK (length(ciphertext) <= 131072),
    nonce TEXT NOT NULL CHECK (length(nonce) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (vault, id),
    FOREIGN KEY (vault, owner) REFERENCES vaults(id, owner)
) STRICT;
CREATE INDEX entries_owner_page ON entries(owner, id);

CREATE TABLE audit_outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    subject TEXT NOT NULL,
    revision INTEGER,
    created_at INTEGER NOT NULL
) STRICT;
