#!/usr/bin/env python3
"""Pull, validate, encrypt, and checkpoint snapshots on an independently administered host."""
from contextlib import closing
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import tempfile
import time
import uuid

MAX_BYTES = 128 * 1024 * 1024
QUERIES = {
    "accounts": "SELECT id, singleton, enrollment_hash, enrollment_expires FROM accounts ORDER BY id",
    "credentials": "SELECT id, owner, passkey FROM credentials ORDER BY id",
    "vaults": "SELECT id, owner, envelope, revision, sequence, deleted FROM vaults ORDER BY id",
    "entries": "SELECT id, vault, owner, ciphertext, nonce, revision, deleted, updated_at FROM entries ORDER BY vault, id",
}


def inspect_snapshot(path):
    """Canonical format v1: ordered rows and fixed-column JSON, UTF-8, compact separators."""
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as database:
        database.execute("PRAGMA trusted_schema = OFF")
        database.execute("PRAGMA query_only = ON")
        deadline = time.monotonic() + 15
        database.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise RuntimeError("database integrity check failed")
        if database.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("database foreign key check failed")
        digest = hashlib.sha256(b"private-vault-state-v1\n")
        for table, query in QUERIES.items():
            digest.update((table + "\n").encode())
            for row in database.execute(query):
                digest.update(json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode() + b"\n")
        events = list(database.execute(
            "SELECT sequence, event_id, operation, subject, revision, created_at FROM audit_outbox ORDER BY sequence LIMIT 100001"
        ))
        # Include sqlite_sequence so a truncated outbox cannot reset the watermark.
        sequence = database.execute(
            "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit_outbox'), 0)"
        ).fetchone()[0]
        if len(events) > 100000 or (events and events[-1][0] != sequence):
            raise RuntimeError("audit watermark mismatch")
        return {"format": 1, "sequence": sequence, "state_sha256": digest.hexdigest(), "events": events}


def compare(previous, current):
    if previous["format"] != current["format"]:
        raise RuntimeError("checkpoint format mismatch")
    if not isinstance(current["sequence"], int) or not 0 <= current["sequence"] <= 100000:
        raise RuntimeError("invalid audit sequence")
    if current["sequence"] < previous["sequence"]:
        raise RuntimeError("ALERT: audit sequence regressed")
    if current["sequence"] == previous["sequence"] and current["state_sha256"] != previous["state_sha256"]:
        raise RuntimeError("ALERT: state changed without an audit sequence advance")
    # JSON checkpoints use lists; SQLite returns tuples. Compare row values.
    old_events = {row[0]: tuple(row) for row in previous["events"]}
    new_events = {row[0]: tuple(row) for row in current["events"]}
    for sequence, row in old_events.items():
        if new_events.get(sequence) != row:
            raise RuntimeError("ALERT: previously observed audit event missing or modified")
    # This initial release never prunes the outbox. Any gap is an error.
    sequences = list(new_events)
    if sequences != list(range(1, current["sequence"] + 1)):
        raise RuntimeError("ALERT: audit sequence gap")


def pull(command, destination):
    """Bound time and bytes even when the remote host sends an endless stream."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 60
    received = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(timeout=remaining):
                    raise RuntimeError("snapshot command timed out")
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                received += len(block)
                if received > MAX_BYTES:
                    raise RuntimeError("snapshot exceeds byte limit")
                destination.write(block)
        if process.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
            raise RuntimeError("snapshot command failed")
        if not received:
            raise RuntimeError("empty snapshot")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def save_checkpoint(archive, snapshot, current, recipient):
    """Create new files only. Advance latest marker after both artifacts are durable."""
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex
    encrypted = archive / (name + ".sqlite.age")
    checkpoint = archive / (name + ".checkpoint.json")
    with encrypted.open("xb") as output:
        subprocess.run(["age", "--recipient", recipient, str(snapshot)], stdout=output, check=True, timeout=60)
        output.flush()
        os.fsync(output.fileno())
    # Audit archive contains identifiers/timestamps, not vault ciphertext or wrapped keys.
    current["collected_at"] = datetime.now(timezone.utc).isoformat()
    current["snapshot_sha256"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    current["backup_file"] = encrypted.name
    with checkpoint.open("x") as output:
        json.dump(current, output, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    marker = archive / ".latest.tmp"
    with marker.open("w") as output:
        output.write(checkpoint.name)
        output.flush()
        os.fsync(output.fileno())
    marker.replace(archive / "latest")
    directory = os.open(archive, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return checkpoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--recipient", required=True, help="age public recipient; private identity stays offline")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- ssh -T ... forced-command-host")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("snapshot command is required")
    os.umask(0o077)
    args.archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive collector lock prevents competing processes from moving the latest marker backward.
    import fcntl
    with (args.archive / ".collector.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="vault-collect-") as directory:
            snapshot = Path(directory) / "snapshot.sqlite"
            with snapshot.open("xb") as output:
                pull(command, output)
            current = inspect_snapshot(snapshot)
            marker = args.archive / "latest"
            if marker.exists():
                previous_name = marker.read_text().strip()
                if Path(previous_name).name != previous_name:
                    raise RuntimeError("invalid checkpoint marker")
                previous = json.loads((args.archive / previous_name).read_text())
            else:
                # Initial collection establishes a baseline, not proof of an uncompromised history.
                previous = {"format": 1, "sequence": 0, "state_sha256": current["state_sha256"], "events": []}
            compare(previous, current)
            checkpoint = save_checkpoint(args.archive, snapshot, current, args.recipient)
            print("checkpoint saved:", checkpoint.name)


if __name__ == "__main__":
    main()
