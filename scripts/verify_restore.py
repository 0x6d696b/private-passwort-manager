#!/usr/bin/env python3
"""Compare a decrypted snapshot with a checkpoint copied from the independent collector."""
import argparse
import hashlib
import json
from pathlib import Path
from collect import inspect_snapshot


def verify(database, checkpoint):
    expected = json.loads(Path(checkpoint).read_text())
    actual = inspect_snapshot(database)
    for key in ("format", "sequence", "state_sha256", "events"):
        # SQLite returns tuples; JSON archive rows are lists.
        if json.dumps(actual[key]) != json.dumps(expected[key]):
            raise RuntimeError("restore does not match independent checkpoint: " + key)
    if hashlib.sha256(Path(database).read_bytes()).hexdigest() != expected["snapshot_sha256"]:
        raise RuntimeError("restore file digest mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("checkpoint", type=Path)
    args = parser.parse_args()
    verify(args.database, args.checkpoint)
    print("restore matches checkpoint; record operator approval externally before serving")


if __name__ == "__main__":
    main()
