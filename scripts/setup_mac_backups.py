#!/usr/bin/env python3
"""Prepare, test, and activate per-user Mac backup jobs. Run manually, without sudo."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys

from install_pi_backup import public_key
from check_checkpoint import check

ROOT = Path(__file__).resolve().parents[1]
LABELS = ('local.private-vault.collect', 'local.private-vault.check')


def private_directory(path):
    if path.is_symlink():
        raise ValueError('private directories must not be symlinks')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError('private directory must be owned by you with mode 0700: ' + str(path))


def atomic(path, data):
    temporary = path.with_name(path.name + '.new')
    with temporary.open('wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def job(label, mode, directory, python):
    return {
        'Label': label,
        'ProgramArguments': [python, str(directory/'program/mac_backup.py'), '--config', str(directory/'config.json'), mode],
        'RunAtLoad': True,
        'StartCalendarInterval': {'Minute': 0} if mode == 'collect' else [{'Minute': 15}, {'Minute': 45}],
        'ProcessType': 'Background',
        'Umask': 0o077,
        'StandardOutPath': str(directory/'logs'/f'{mode}.log'),
        'StandardErrorPath': str(directory/'logs'/f'{mode}.error.log'),
    }


def prepare(directory, recipient, host):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', host):
        raise ValueError('host must be a DNS hostname or IPv4 address')
    age = shutil.which('age')
    keygen = shutil.which('ssh-keygen')
    python = shutil.which('python3')
    if not age or not keygen or not python:
        raise ValueError('age, ssh-keygen, and python3 are required')
    # Validate the recipient with age itself; no recovery private key is read.
    subprocess.run([age, '--recipient', recipient], input=b'public-recipient-validation',
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=15)
    private_directory(directory)
    for name in ('ssh', 'archive', 'program', 'logs', 'launchagents'):
        private_directory(directory/name)
    config_file = directory/'config.json'
    if config_file.exists():
        previous = json.loads(config_file.read_text())
        if previous['host'] != host or previous['recipient'] != recipient:
            raise ValueError('existing host/recipient differ; use a separate backup directory')
    identity = directory/'ssh/client_ed25519'
    if not identity.exists():
        subprocess.run([keygen, '-t', 'ed25519', '-N', '', '-C', 'private-vault-backup', '-f', str(identity)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if identity.is_symlink() or not identity.with_suffix('.pub').is_file():
        raise ValueError('unexpected SSH identity files')
    identity.chmod(0o600)
    for name in ('mac_backup.py', 'collect.py', 'check_checkpoint.py'):
        atomic(directory/'program'/name, (ROOT/'scripts'/name).read_bytes())
    config = {
        'host': host, 'recipient': recipient, 'age_binary': age, 'python': python,
        'archive': str(directory/'archive'), 'ssh_identity': str(identity),
        'known_hosts': str(directory/'ssh/known_hosts'),
        'archive_budget_bytes': 5 * 1024**3,
    }
    atomic(config_file, (json.dumps(config, indent=2)+'\n').encode())
    for label, mode in zip(LABELS, ('collect','check')):
        atomic(directory/'launchagents'/(label+'.plist'), plistlib.dumps(job(label, mode, directory, python)))
    print('Prepared; no background jobs have been installed or started.')
    print('Public SSH key to transfer to the Pi: ' + str(identity.with_suffix('.pub')))
    print(identity.with_suffix('.pub').read_text().strip())


def trust_host(directory, key_file):
    config = json.loads((directory/'config.json').read_text())
    entry = config['host'] + ' ' + public_key(key_file.read_text()) + '\n'
    target = Path(config['known_hosts'])
    if target.exists() and target.read_text() != entry:
        raise ValueError('host pin differs; verify rotation out of band before replacing it manually')
    atomic(target, entry.encode())
    print('Pinned the supplied Pi host key; no network key scan was used.')


def activate(directory):
    if sys.platform != 'darwin':
        raise ValueError('activation requires macOS launchd')
    config = json.loads((directory/'config.json').read_text())
    status = json.loads((directory/'status.json').read_text())
    if status.get('last_attempt_ok') is not True:
        raise ValueError('a successful manual collection is required before scheduling')
    check(Path(config['archive']), 86400)
    destination = Path.home()/'Library/LaunchAgents'
    destination.mkdir(parents=True, exist_ok=True)
    for label in LABELS:
        target = destination/(label+'.plist')
        if target.exists():
            raise ValueError('job already installed; remove it before reactivating: ' + label)
    installed = []
    try:
        for label in LABELS:
            target = destination/(label+'.plist')
            atomic(target, (directory/'launchagents'/target.name).read_bytes())
            installed.append((label,target))
            subprocess.run(['/bin/launchctl', 'bootstrap', 'gui/'+str(os.getuid()), str(target)], check=True)
    except BaseException:
        for label,target in installed:
            subprocess.run(['/bin/launchctl','bootout','gui/'+str(os.getuid())+'/'+label], check=False)
            target.unlink(missing_ok=True)
        raise
    print('Installed hourly collection and twice-hourly checks for the logged-in Mac user.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path.home()/'Library/Application Support/PrivateVaultBackups')
    commands = parser.add_subparsers(dest='mode', required=True)
    initialize = commands.add_parser('prepare')
    initialize.add_argument('--recipient', required=True)
    initialize.add_argument('--host', help='private hostname; preserves the existing configuration when omitted')
    trust = commands.add_parser('trust-host')
    trust.add_argument('--host-key', type=Path, required=True)
    for mode in ('collect', 'check', 'status', 'activate', 'remove'):
        commands.add_parser(mode)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run as your normal Mac user, without sudo')
    os.umask(0o077)
    directory = args.directory.expanduser().absolute()
    if args.mode == 'prepare':
        previous = directory/'config.json'
        host = args.host or (json.loads(previous.read_text())['host'] if previous.exists() else 'vault.home.arpa')
        prepare(directory, args.recipient, host)
    elif args.mode == 'trust-host':
        trust_host(directory, args.host_key)
    elif args.mode == 'activate':
        activate(directory)
    elif args.mode == 'remove':
        if sys.platform != 'darwin':
            parser.error('launchd removal requires macOS')
        for label in LABELS:
            subprocess.run(['/bin/launchctl','bootout','gui/'+str(os.getuid())+'/'+label], check=False)
            (Path.home()/'Library/LaunchAgents'/(label+'.plist')).unlink(missing_ok=True)
        print('Jobs removed. Backups, keys, and Pi authorization were not deleted.')
    else:
        config = json.loads((directory/'config.json').read_text())
        result = subprocess.run([config['python'], str(directory/'program/mac_backup.py'), '--config', str(directory/'config.json'), args.mode])
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
