#!/usr/bin/env python3
"""Install the dedicated snapshot-only SSH account on the Pi. Run manually as root."""
import argparse
import base64
import ipaddress
import os
from pathlib import Path
import pwd
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "vault-backup"
ACCOUNT_HOME = Path("/var/lib/private-vault-backup")


def public_key(text):
    lines = text.strip().splitlines()
    if len(lines) != 1:
        raise ValueError("provide exactly one Ed25519 public key")
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("an Ed25519 public key without authorized_keys options is required")
    raw = base64.b64decode(parts[1], validate=True)
    if len(raw) != 51 or raw[:15] != struct.pack(">I", 11) + b"ssh-ed25519" or raw[15:19] != struct.pack(">I", 32):
        raise ValueError("invalid Ed25519 key encoding")
    return "ssh-ed25519 " + parts[1]


def authorized_key(text, allowed_source):
    network = ipaddress.IPv4Network(allowed_source, strict=True)
    if not network.is_private or network.prefixlen < 8:
        raise ValueError("backup source must be a private IPv4 subnet with prefix length >= 8")
    return ('restrict,from="' + str(network) + '",command="/usr/bin/sudo -n /usr/local/sbin/private-vault-snapshot" '
            + public_key(text) + ' private-vault-mac\n')


def run(*args):
    return subprocess.run(args, check=True)


def install(source, destination, mode):
    run("/usr/bin/install", "-o", "root", "-g", "root", "-m", mode, str(source), str(destination))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--allowed-source", required=True, help="private IPv4 CIDR allowed to export snapshots")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run this installer as root on the Pi")
    key_line = authorized_key(args.public_key.read_text(), args.allowed_source)
    effective = subprocess.check_output(["/usr/sbin/sshd", "-T"]).decode().splitlines()
    if "usepam yes" not in effective:
        parser.error("this locked-password account profile requires Debian's UsePAM yes configuration")
    if not Path("/usr/bin/docker").is_file():
        parser.error("expected Docker at /usr/bin/docker")
    try:
        account = pwd.getpwnam(ACCOUNT)
        if account.pw_dir != str(ACCOUNT_HOME) or account.pw_shell != "/bin/sh":
            parser.error("existing backup account does not match the managed profile")
    except KeyError:
        run("/usr/sbin/useradd", "--system", "--user-group", "--home-dir", str(ACCOUNT_HOME), "--shell", "/bin/sh", ACCOUNT)
        account = pwd.getpwnam(ACCOUNT)
    groups = subprocess.check_output(["/usr/bin/id", "-nG", ACCOUNT]).decode().split()
    if set(groups) & {"docker", "sudo", "root", "adm"}:
        parser.error("backup account must not belong to privileged groups")
    run("/usr/sbin/usermod", "--lock", ACCOUNT)
    run("/usr/bin/install", "-d", "-o", "root", "-g", ACCOUNT, "-m", "0750", str(ACCOUNT_HOME))
    run("/usr/bin/install", "-d", "-o", "root", "-g", ACCOUNT, "-m", "0750", str(ACCOUNT_HOME / ".ssh"))
    # Root-owned home and .ssh prevent the account from replacing its own keys.
    with tempfile.TemporaryDirectory(prefix="vault-backup-install-") as directory:
        directory = Path(directory)
        keys = directory / "authorized_keys"
        keys.write_text(key_line)
        run("/usr/bin/install", "-o", "root", "-g", ACCOUNT, "-m", "0640", str(keys), str(ACCOUNT_HOME / ".ssh/authorized_keys"))
        sudoers = ROOT / "deploy/backup/vault-backup.sudoers"
        run("/usr/sbin/visudo", "-cf", str(sudoers))
        install(ROOT / "deploy/backup/pi-export-snapshot.py", "/usr/local/sbin/private-vault-snapshot", "0755")
        install(sudoers, "/etc/sudoers.d/private-vault-backup", "0440")
    # No sshd configuration changes or reload are needed: restrictions live on
    # the root-owned key, and the account's password is locked.
    print("Snapshot-only SSH account installed; no Docker-group membership or general sudo access.")
    print("Transfer this public host key to the Mac through your existing trusted connection:")
    print(Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().strip())


if __name__ == "__main__":
    main()
