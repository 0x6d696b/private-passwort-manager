#!/usr/bin/env python3
"""Run the Mac's installed collector/checker; launchd invokes this without a shell."""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from check_checkpoint import check

MAX_AGE = 24 * 60 * 60
ALERT_INTERVAL = 4 * 60 * 60


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        json.dump(value, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def ssh_arguments(config):
    # OpenSSH parses -o values again, even with shell-free subprocess arguments.
    known_hosts = config['known_hosts']
    if any(character in known_hosts for character in ('\"', '\n', '\r', '\\')):
        raise ValueError('unsupported character in SSH known-hosts path')
    return ['/usr/bin/ssh', '-4', '-T', '-F', '/dev/null',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'UpdateHostKeys=no',
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
            '-o', 'ClearAllForwardings=yes',
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'UserKnownHostsFile="' + known_hosts + '"',
            '-i', config['ssh_identity'], 'vault-backup@' + config['host']]


def latest_health(archive):
    collected = None
    try:
        name = (archive / 'latest').read_text().strip()
        if Path(name).name != name:
            return False, None
        collected = json.loads((archive / name).read_text())['collected_at']
        check(archive, MAX_AGE)
        return True, collected
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        return False, collected


def notify(state, mode, now=None):
    now = time.time() if now is None else now
    previous = state.get('last_alert_at', 0)
    if mode == state.get('last_alert_kind') and 0 <= now - previous < ALERT_INTERVAL:
        return
    text = ('Private Vault backup is missing, invalid, or more than 24 hours old. Check your Pi connection and backup status.'
            if mode == 'overdue' else 'Private Vault backup storage needs attention. Check the archive size and free disk space.')
    if sys.platform == 'darwin':
        # Fixed messages only: no paths, keys, record contents, or shell interpolation.
        result = subprocess.run(['/usr/bin/osascript', '-e',
            'on run argv\ndisplay notification (item 1 of argv) with title "Private Vault backups"\nend run', text],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
        state['notification_requested'] = result.returncode == 0
    else:
        state['notification_requested'] = False
    state['last_alert_at'] = now
    state['last_alert_kind'] = mode


def storage_available(config):
    archive = Path(config['archive'])
    used = sum(item.stat().st_size for item in archive.iterdir() if item.is_file())
    return used < config['archive_budget_bytes'] and shutil.disk_usage(archive).free >= 512 * 1024 * 1024


def execute(config, mode, state):
    archive = Path(config['archive'])
    healthy, collected = latest_health(archive)
    state['checked_at'] = datetime.now(timezone.utc).isoformat()
    state['healthy'] = healthy
    state['last_success'] = collected
    if not healthy:
        notify(state, 'overdue')
    if mode == 'collect':
        if not storage_available(config):
            state['last_attempt_ok'] = False
            state['last_error'] = 'archive budget reached or free disk space below 512 MiB; no archives deleted'
            notify(state, 'storage')
            return 1
        arguments = [sys.executable, str(Path(__file__).with_name('collect.py')),
                     '--archive', config['archive'], '--recipient', config['recipient'], '--', *ssh_arguments(config)]
        state['last_attempt_at'] = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(arguments, capture_output=True, timeout=180, check=False)
            success = result.returncode == 0
        except subprocess.TimeoutExpired:
            success = False
        state['last_attempt_ok'] = success
        state['last_error'] = None if success else 'snapshot collection failed; verify restricted SSH and Pi availability'
        healthy, collected = latest_health(archive)
        state['healthy'] = healthy
        state['last_success'] = collected
        if success and healthy:
            state.pop('last_alert_kind', None)
        return 0 if success else 1
    return 0 if healthy else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('mode', choices=['collect', 'check', 'status'])
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(args.config.read_text())
    # launchd has a minimal PATH; expose only the configured age directory and system tools.
    os.environ['PATH'] = str(Path(config['age_binary']).parent) + ':/usr/bin:/bin:/usr/sbin:/sbin'
    state_file = args.config.with_name('status.json')
    if args.mode == 'status':
        print(state_file.read_text() if state_file.exists() else 'No backup run recorded yet.')
        return
    with args.config.with_name('runner.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another collector/check run is active; leaving state unchanged.')
            return
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        code = execute(config, args.mode, state)
        write_json(state_file, state)
        print('Backup check completed; healthy=' + str(state.get('healthy', False)))
        raise SystemExit(code)


if __name__ == '__main__':
    main()
