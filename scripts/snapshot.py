#!/usr/bin/env python3
"""Emit a consistent SQLite snapshot to stdout; run through a restricted SSH command."""
from contextlib import closing
import argparse
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import time

MAX_BYTES = 128 * 1024 * 1024


def snapshot(database, output):
    deadline = time.monotonic() + 45
    with tempfile.TemporaryDirectory(prefix="vault-snapshot-") as directory:
        target = Path(directory) / "snapshot.sqlite"
        target.touch(mode=0o600)

        def progress(status, remaining, total):
            if time.monotonic() > deadline or target.stat().st_size > MAX_BYTES:
                raise RuntimeError("snapshot limit exceeded")

        with closing(sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True, timeout=3)) as source:
            with closing(sqlite3.connect(target)) as backup:
                source.backup(backup, pages=128, progress=progress, sleep=0.05)
        if target.stat().st_size > MAX_BYTES:
            raise RuntimeError("snapshot limit exceeded")
        with target.open("rb") as stream:
            shutil.copyfileobj(stream, output, length=65536)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    snapshot(args.database, sys.stdout.buffer)


if __name__ == "__main__":
    main()
