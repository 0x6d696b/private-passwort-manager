# Mac Backup Collector

Hostnames and network ranges here are examples. Use your own private hostname and source CIDR. Existing Mac configuration is preserved when `prepare` omits `--host`.

The Mac pulls an encrypted snapshot hourly from `vault.home.arpa`. A separate check runs at minutes 15 and 45 and requests a local notification when the latest checkpoint is missing, invalid, or over 24 hours old. Both jobs run at login; calendar events missed during sleep coalesce on wake. This is not continuous monitoring: the Mac must be awake, logged in, and on the LAN to collect. Notification delivery depends on macOS settings.

## 1. Prepare on the Mac

Run from this repository as your normal user, without `sudo`. Required tools: Python 3, `age`, and OpenSSH. Create a new, passphrase-encrypted recovery identity; never paste its contents or passphrase into chat. If you already have a production recovery identity, reuse its public recipient instead.

```sh
umask 077
set -o pipefail
mkdir -p -m 700 "$HOME/PrivateVaultRecovery"
age-keygen | age --passphrase --output "$HOME/PrivateVaultRecovery/identity.age"
vault_recipient="$(age --decrypt "$HOME/PrivateVaultRecovery/identity.age" | age-keygen -y)"
python3 scripts/setup_mac_backups.py prepare --recipient "$vault_recipient" --host vault.home.arpa
```

Choose a strong recovery passphrase. Keep an additional copy of the encrypted identity somewhere independent and preferably offline. The only copy on the Mac can be lost together with its backups. Preparation creates a separate unencrypted SSH key, restricted on the Pi to snapshot export; unattended jobs never need the recovery identity or its passphrase. No jobs start yet.

## 2. Install the Pi export account

Transfer only the generated **public** SSH key over your existing trusted administrator connection (replace `YOUR_PI_USER`):

```sh
scp "$HOME/Library/Application Support/PrivateVaultBackups/ssh/client_ed25519.pub" \
  YOUR_PI_USER@vault.home.arpa:/tmp/private-vault-mac.pub
```

Update this repository on the Pi, then run there:

```sh
sudo python3 scripts/install_pi_backup.py --public-key /tmp/private-vault-mac.pub --allowed-source 192.168.50.0/24
```

This creates `vault-backup` with a locked password and root-owned authorized keys. The key permits connections from `192.168.50.0/24`, disables forwarding and PTYs, and forces an argument-free snapshot helper. The account has no Docker-group membership. Its sole sudo permission exports from the running Compose project `private-vault`, service `api`, using the container's unprivileged user. No SSH configuration reload is needed. Debian's `UsePAM yes` is required; unusual SSH access policies may require separate administrator review.

## 3. Pin the Pi host identity and test

Retrieve the public host key through your already trusted administrator connection. Compare it with the installer output; do not use an unverified network key scan.

```sh
scp YOUR_PI_USER@vault.home.arpa:/etc/ssh/ssh_host_ed25519_key.pub /tmp/private-vault-pi-host.pub
python3 scripts/setup_mac_backups.py trust-host --host-key /tmp/private-vault-pi-host.pub
python3 scripts/setup_mac_backups.py collect
python3 scripts/setup_mac_backups.py check
python3 scripts/setup_mac_backups.py status
```

A host-key change fails closed. Investigate it before replacing the pin. Verify a real collection succeeds before activating:

```sh
python3 scripts/setup_mac_backups.py activate
```

Activation refuses to proceed without a successful recent collection. Jobs run under your user through `launchd`, with no shell or SSH agent. Alerts repeat at most every four hours per alert kind. A request accepted by `osascript` does not prove a notification was displayed; check macOS notification settings.

## Operation and recovery

Files live under `~/Library/Application Support/PrivateVaultBackups/`: encrypted snapshots and independent checkpoints in `archive/`, status in `status.json`, and job output in `logs/`. Installation copies the scripts there; repository changes require preparing again and, for schedule changes, removing/reactivating the jobs.

Collection stops when the archive reaches a 5 GiB soft budget or free disk space falls below 512 MiB, and requests a storage warning. One collection can cross the budget. Nothing is automatically pruned; review retention before manually removing old backup/checkpoint pairs, preserving the pair referenced by `latest`. Collection errors leave previous backups intact. The Pi cannot write to the Mac archive using the export key.

For recovery, decrypt a selected snapshot with the encrypted identity (age prompts for its passphrase), then verify it against its independent checkpoint using the repository's recovery procedure. The age identity restores the backend snapshot; decrypting vault entries still requires the future client's vault credentials. Periodically exercise the documented restore drill.

```sh
python3 scripts/setup_mac_backups.py remove
```

Removal unloads only these two jobs and preserves archives and keys. To revoke export access, separately remove the managed public key from `/var/lib/private-vault-backup/.ssh/authorized_keys` on the Pi as administrator. Live Pi SSH export, scheduled execution, notification delivery, and recovery with your production identity still require verification on your devices.
