#!/usr/bin/env python3
"""Run independently of collection to alert when successful checkpoints stop arriving."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path


def check(archive, max_age):
    name = (archive / "latest").read_text().strip()
    if Path(name).name != name:
        raise RuntimeError("invalid checkpoint marker")
    checkpoint = json.loads((archive / name).read_text())
    timestamp = datetime.fromisoformat(checkpoint["collected_at"])
    age = (datetime.now(timezone.utc) - timestamp).total_seconds()
    if age < -60 or age > max_age:
        raise RuntimeError("ALERT: checkpoint is stale or its timestamp is in the future")
    if not (archive / checkpoint["backup_file"]).is_file():
        raise RuntimeError("ALERT: encrypted backup is missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--max-age", type=int, default=900)
    args = parser.parse_args()
    if args.max_age <= 0:
        parser.error("max-age must be positive")
    check(args.archive, args.max_age)
    print("checkpoint is current")


if __name__ == "__main__":
    main()
