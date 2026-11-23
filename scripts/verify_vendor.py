#!/usr/bin/env python3
"""Verify vendored files match the reviewed provenance manifest."""
import hashlib
import json
from pathlib import Path


def main():
    vendor = Path(__file__).resolve().parents[1] / "vendor"
    for record in json.loads((vendor / "provenance.json").read_text()):
        directory = vendor / record["crate"]
        actual = {
            str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob("*")) if path.is_file()
        }
        if actual != record["files"]:
            raise SystemExit("vendored source differs from reviewed manifest: " + record["crate"])
    print("vendored source hashes match provenance manifest")


if __name__ == "__main__":
    main()
