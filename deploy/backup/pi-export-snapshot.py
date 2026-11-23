#!/usr/bin/python3 -I
"""Root-owned, argument-free export helper. Invoked only by the backup account's sudo rule."""
import os
import re
import subprocess
import sys


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise SystemExit("snapshot export requires root and accepts no arguments")
    docker = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/root"}
    result = subprocess.run(docker + ["ps", "--filter", "label=com.docker.compose.project=private-vault",
        "--filter", "label=com.docker.compose.service=api", "--format", "{{.ID}}"],
        env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    identifiers = result.stdout.decode().split()
    if len(identifiers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", identifiers[0]):
        raise SystemExit("exactly one running Private Vault API is required")
    # Never evaluate SSH_ORIGINAL_COMMAND or accept a client-supplied Docker argument.
    subprocess.run(docker + ["exec", "--user", "10001:10001", identifiers[0],
        "python3", "-I", "/app/scripts/snapshot.py", "/data/vault.sqlite"],
        env=environment, check=True, timeout=55)


if __name__ == "__main__":
    main()
