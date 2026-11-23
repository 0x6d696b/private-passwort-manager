# Password Manager: Quick Operations Guide

**Public examples:** replace the hostname, addresses, usernames, and repository paths with your own. Keep real deployment notes in ignored `OPERATIONS.local.md` and settings in ignored `.env.pi`; never publish those files.

## Access and important locations

Open **https://vault.home.arpa/** on your home network. Example server: **192.168.50.10**. Remote access uses the router’s WireGuard VPN; connect the tunnel before opening the vault.

| Location | What it contains |
| --- | --- |
| Pi: `/opt/private-vault/` | Application repository; `.env.pi` selects hostname, LAN binding, and images |
| Mac: `~/Projects/private-vault/` | Repository, client build, tests, and backup tools |
| Pi Docker volume: `private-vault_vault_data` | Database, mounted inside the API at `/data/vault.sqlite` |
| Pi volumes: `private-vault_caddy_data`, `private-vault_caddy_config` | HTTPS certificate authority and proxy state |
| Mac: `~/Library/Application Support/PrivateVaultBackups/archive/` | Encrypted `*.sqlite.age` backups, matching `*.checkpoint.json` files, and `latest` marker |
| Mac: `~/Library/Application Support/PrivateVaultBackups/` | `config.json`, `status.json`, `logs/`, installed collector scripts, and restricted SSH key in `ssh/` |
| Mac: `~/PrivateVaultRecovery/identity.age` | Passphrase-encrypted backup recovery identity; keep another copy offline |
| Mac: `~/PrivateVaultCertificates/pi-root.crt` | Pi's public HTTPS root certificate |

The age recovery passphrase decrypts backups. The **vault master password** decrypts the entries inside them. Keep both; neither replaces the other.

## Everyday commands

**Pi:** run from the repository; define this shortcut in each new terminal:

```sh
cd /opt/private-vault
vault_pi() {
  sudo docker compose --env-file .env.pi -p private-vault \
    -f compose.yaml -f deploy/compose.pi.yaml "$@"
}
vault_pi ps
vault_pi logs --tail 50 api proxy
```

Other useful commands:

```sh
vault_pi stop api proxy                          # Stop the vault
vault_pi up -d --no-build --pull never            # Start it
vault_pi restart api                             # Restart API; sessions expire
sudo systemctl is-active private-vault-firewall.service
sudo iptables -vnL PV_PI_HTTPS                    # LAN allow/drop counters
sudo docker exec private-vault-api-1 cat /sys/fs/cgroup/memory.max
sudo docker exec private-vault-proxy-1 cat /sys/fs/cgroup/memory.max
```

Memory ceilings should be `268435456` (API, 256 MiB) and `201326592` (proxy, 192 MiB). Firewall settings are in root-owned `/etc/private-vault/firewall.conf`. Pi boot settings are in `/boot/firmware/cmdline.txt`: keep one line and retain `cgroup_enable=memory`.

**Mac:** run from the repository:

```sh
curl --fail --cacert "$HOME/PrivateVaultCertificates/pi-root.crt" https://vault.home.arpa/health
python3 scripts/setup_mac_backups.py collect      # Make a backup now
python3 scripts/setup_mac_backups.py status       # Last success/error
open "$HOME/Library/Application Support/PrivateVaultBackups/archive"
```

Backups run hourly while logged in and awake, with LAN access. Checks warn when a backup is over 24 hours old. The archive has a 5 GiB soft budget; nothing is automatically deleted. For setup, updates, or removal, see [Mac backups](deploy/mac-backups.md). Scheduled jobs currently depend on the repository's `venv/bin/python3`; preserve that environment or prepare/reinstall the jobs with another interpreter.

## Remote access through WireGuard

The verified setup uses the router’s WireGuard server and a separate Mac profile. From outside home, connect the Mac to the internet, activate its WireGuard tunnel, then open the vault using its existing private hostname. Passkey sign-in and the vault master password are still required.

The connection was tested from a phone hotspot with a successful handshake and vault access. With DS-Lite at home, the remote network needs working IPv6; IPv4-only networks cannot reach this VPN endpoint directly. MyFRITZ! supplies the router endpoint name. No public HTTPS forwarding to the vault is needed.

If access fails, check the WireGuard handshake first, then private DNS and HTTPS reachability. Keep the Pi firewall restrictions in place. A successful tunnel is not a reason to open port 443 to the internet.

Create a separate WireGuard profile for each device. Configuration files and QR codes contain private keys: keep them outside Git and revoke the router’s corresponding profile if a device is lost. A newly configured device also needs to trust the verified public vault HTTPS root CA. The vault’s URL/RP ID must remain stable for existing passkeys.

## Reinstall on another machine

1. Install Git, Docker Engine, and Compose on the Linux host; on the Mac install Node.js 20+, Python 3.11+, and `age`. Clone your GitHub repository. Never commit keys, tokens, or `.env.pi`.
2. On the Mac, run `npm --prefix client ci --ignore-scripts` and `npm --prefix client run build`.
3. Follow [Pi deployment](deploy/raspberry-pi.md) to build ARM64 images, transfer them, and load them. Start with `.env.pi.example` (loopback-only); review addresses, image digests, and subnet conflicts for a different machine.
4. **New empty installation:** run migrations and `init` while the API is stopped. **Existing vault:** restore its verified backup instead; do not initialize a replacement account.
5. Install the scoped firewall before publishing LAN HTTPS. Configure DNS, trust the public HTTPS CA, and verify `/health`. Keep the same hostname/RP ID when recovering existing passkeys. A new CA needs renewed browser trust.
6. Reinstall the [Mac collector](deploy/mac-backups.md), verify the new Pi SSH host key, and complete a manual collection before activating its schedule. Do not discard old checkpoints or replace an existing host pin without verification.

## Decrypt and restore a backup

On the Mac, choose a backup and its matching checkpoint from `archive/`. Replace `SELECTED` below with their shared filename prefix:

```sh
umask 077
archive="$HOME/Library/Application Support/PrivateVaultBackups/archive"
restore_dir="$(mktemp -d /tmp/private-vault-restore.XXXXXX)"
age --decrypt --identity "$HOME/PrivateVaultRecovery/identity.age" \
  --output "$restore_dir/vault.sqlite" "$archive/SELECTED.sqlite.age"
python3 scripts/verify_restore.py "$restore_dir/vault.sqlite" \
  "$archive/SELECTED.checkpoint.json"
```

Enter the recovery passphrase locally. **Continue only if verification succeeds.** For a recovery test, remove the temporary plaintext directory afterward; deletion does not guarantee forensic erasure.

For actual recovery: stop the API; preserve the existing data volume; install the verified database into a **clean volume** as UID/GID `10001:10001`, with directory mode `0700` and database mode `0600`. Never mix it with old WAL/SHM files. Point the `vault_data` Compose volume at that replacement, run migrations while stopped, and start the API. Verify login, a synthetic entry, HTTPS, and a fresh backup. Keep the original volume until recovery is confirmed. See [recovery details](README.md#independent-backups-and-monitoring).

If passkeys are lost, use `recover --token-file /data/NEW-UNIQUE-NAME.token` while stopped; it **removes existing passkeys** and issues a ten-minute enrollment token. Use `init` only when no account exists. Never share enrollment tokens or recovery identities.

## Keeping this guide current

Whenever project changes affect commands, paths, installation, authentication, backup/recovery, networking, or operational limits, update this guide in the same change. Use anonymized examples here; preserve machine-specific notes only in ignored `OPERATIONS.local.md`. Record verified behavior, and mark pending features clearly. This is a development maintenance rule, not a background monitoring service.
