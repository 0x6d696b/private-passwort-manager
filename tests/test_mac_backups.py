"""Collector installation, scheduling, notification, and SSH boundary checks."""
from datetime import datetime, timedelta, timezone
import base64
import importlib.util
import json
import io
from contextlib import redirect_stdout
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import mac_backup
import setup_mac_backups as setup
from install_pi_backup import public_key, authorized_key

PUBLIC = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(range(32))).decode()


class MacBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root/'archive'
        self.archive.mkdir(mode=0o700)

    def checkpoint(self, hours=0):
        (self.archive/'latest').write_text('current.json')
        collected = (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat()
        (self.archive/'current.json').write_text(json.dumps({'collected_at':collected,'backup_file':'backup.age'}))
        (self.archive/'backup.age').write_bytes(b'test encrypted archive fixture')
        return collected

    def config(self):
        return {'archive':str(self.archive),'host':'vault.home.arpa', 'recipient':'public-recipient',
                'ssh_identity':str(self.root/'ssh-key'), 'known_hosts':str(self.root/'known_hosts'),
                'archive_budget_bytes':5*1024**3}

    def test_jobs_are_hourly_and_independent_and_use_structured_arguments(self):
        directory = self.root/'path with spaces'
        collector = setup.job(setup.LABELS[0],'collect',directory,'/usr/bin/python3')
        checker = setup.job(setup.LABELS[1],'check',directory,'/usr/bin/python3')
        for entry in (collector,checker):
            self.assertTrue(entry['RunAtLoad'])
            self.assertNotIn('KeepAlive',entry)
            self.assertNotIn('/bin/sh', entry['ProgramArguments'])
            self.assertEqual(plistlib.loads(plistlib.dumps(entry)),entry)
        self.assertEqual(collector['StartCalendarInterval'],{'Minute':0})
        self.assertEqual(checker['StartCalendarInterval'],[{'Minute':15},{'Minute':45}])

    def test_ssh_pins_host_and_identity_and_disables_forwarding_and_agent(self):
        args = mac_backup.ssh_arguments(self.config())
        for item in ('StrictHostKeyChecking=yes','IdentitiesOnly=yes','IdentityAgent=none',
                     'ClearAllForwardings=yes','UpdateHostKeys=no','BatchMode=yes'):
            self.assertIn(item,args)
        self.assertEqual(args[-1], 'vault-backup@vault.home.arpa')
        self.assertEqual(args[args.index('-F')+1],'/dev/null')
        self.assertIn('GlobalKnownHostsFile=/dev/null',args)

    def test_openssh_parses_known_hosts_path_with_spaces_as_one_file(self):
        config = self.config()
        config['known_hosts'] = str(self.root/'Application  Support/known_hosts')
        args = mac_backup.ssh_arguments(config)
        result = subprocess.run([args[0], '-G', *args[1:]],
                                capture_output=True, text=True, check=True)
        line = next(line for line in result.stdout.splitlines()
                    if line.startswith('userknownhostsfile '))
        self.assertEqual(line, 'userknownhostsfile ' + config['known_hosts'])

    def test_overdue_check_retains_last_success_and_requests_warning(self):
        collected = self.checkpoint(hours=25)
        state = {}
        with patch.object(mac_backup,'notify') as notify:
            result = mac_backup.execute(self.config(),'check',state)
        self.assertEqual(result,1)
        self.assertFalse(state['healthy'])
        self.assertEqual(state['last_success'],collected)
        notify.assert_called_once_with(state,'overdue')

    def test_successful_check_does_not_warn(self):
        self.checkpoint()
        with patch.object(mac_backup,'notify') as notify:
            self.assertEqual(mac_backup.execute(self.config(),'check',{}),0)
        notify.assert_not_called()

    def test_collection_failure_preserves_latest_checkpoint(self):
        self.checkpoint()
        before = (self.archive/'latest').read_bytes()
        state = {}
        with patch.object(mac_backup.subprocess,'run',return_value=SimpleNamespace(returncode=1)), patch.object(mac_backup,'notify'):
            self.assertEqual(mac_backup.execute(self.config(),'collect',state),1)
        self.assertFalse(state['last_attempt_ok'])
        self.assertEqual((self.archive/'latest').read_bytes(),before)
        self.assertTrue(state['healthy'])  # Last successful backup is still recent.

    def test_full_archive_budget_stops_collection_without_deleting_backups(self):
        self.checkpoint()
        config = dict(self.config(), archive_budget_bytes=1)
        files = {p.name:p.read_bytes() for p in self.archive.iterdir()}
        with patch.object(mac_backup.subprocess,'run') as run, patch.object(mac_backup,'notify'):
            self.assertEqual(mac_backup.execute(config,'collect',{}),1)
        run.assert_not_called()
        self.assertEqual({p.name:p.read_bytes() for p in self.archive.iterdir()},files)

    def test_notification_cooldown_avoids_repeated_alerts(self):
        state = {}
        with patch.object(mac_backup.sys,'platform','darwin'), patch.object(mac_backup.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            mac_backup.notify(state,'overdue',now=100000)
            mac_backup.notify(state,'overdue',now=100001)
            self.assertEqual(run.call_count,1)
            mac_backup.notify(state,'overdue',now=120000)
            self.assertEqual(run.call_count,2)
        self.assertTrue(state['notification_requested'])

    def test_public_key_options_and_multiple_keys_cannot_be_injected(self):
        self.assertEqual(public_key(PUBLIC+' user comment'),PUBLIC)
        for text in ('command="sh" '+PUBLIC, PUBLIC+'\n'+PUBLIC, 'ssh-ed25519 AAAA', 'ssh-rsa AAAA'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                public_key(text)
        entry = authorized_key(PUBLIC, '192.168.50.0/24')
        self.assertTrue(entry.startswith('restrict,from="192.168.50.0/24",command='))
        self.assertIn('/usr/bin/sudo -n /usr/local/sbin/private-vault-snapshot',entry)

    def test_backup_source_cidr_rejects_public_broad_and_injected_values(self):
        for source in ('0.0.0.0/0', '8.8.8.0/24', '192.168.50.0/24",command="sh', '192.168.50.1/24'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                authorized_key(PUBLIC, source)

    def test_prepare_cli_preserves_existing_host_when_omitted(self):
        directory = self.root/'existing-runtime'
        directory.mkdir()
        (directory/'config.json').write_text(json.dumps({'host':'existing.home.arpa'}))
        with patch.object(sys, 'argv', ['setup_mac_backups.py','--directory',str(directory),
                                      'prepare','--recipient','public-recipient']), \
             patch.object(setup.os, 'geteuid', return_value=501), \
             patch.object(setup, 'prepare') as prepare:
            setup.main()
        prepare.assert_called_once_with(directory, 'public-recipient', 'existing.home.arpa')

    def test_pinned_host_cannot_be_silently_changed(self):
        root = self.root/'runtime'
        (root/'ssh').mkdir(parents=True)
        (root/'config.json').write_text(json.dumps({'host':'vault.home.arpa','known_hosts':str(root/'ssh/known_hosts')}))
        key = self.root/'host.pub'; key.write_text(PUBLIC)
        setup.trust_host(root,key)
        first = (root/'ssh/known_hosts').read_bytes()
        setup.trust_host(root,key)
        self.assertEqual((root/'ssh/known_hosts').read_bytes(),first)
        (root/'ssh/known_hosts').write_text('different trusted key\n')
        with self.assertRaises(ValueError):
            setup.trust_host(root,key)

    def test_prepare_creates_private_runtime_without_activating_jobs(self):
        from recovery_validation import keypair
        recipient = keypair(self.root/'test-age-identity')
        directory = self.root/'runtime with spaces'
        with redirect_stdout(io.StringIO()):
            setup.prepare(directory,recipient,'vault.home.arpa')
        config = json.loads((directory/'config.json').read_text())
        self.assertEqual(config['recipient'],recipient)
        self.assertNotIn(str(self.root/'test-age-identity'),json.dumps(config))
        self.assertEqual((directory/'config.json').stat().st_mode & 0o777,0o600)
        self.assertEqual((directory/'ssh/client_ed25519').stat().st_mode & 0o777,0o600)
        self.assertFalse((directory/'ssh/known_hosts').exists())
        result = subprocess.run([config['python'], str(directory/'program/mac_backup.py'), '--config', str(directory/'config.json'), 'status'],
                                check=True,capture_output=True)
        self.assertIn(b'No backup run recorded',result.stdout)
        with self.assertRaises(ValueError):
            setup.prepare(directory,recipient,'different-host')

    def test_snapshot_helper_rejects_arguments_before_invoking_docker(self):
        spec = importlib.util.spec_from_file_location('pi_export',ROOT/'deploy/backup/pi-export-snapshot.py')
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        with patch.object(helper.sys,'argv',['helper','--bad']), patch.object(helper.os,'geteuid',return_value=0), patch.object(helper.subprocess,'run') as run:
            with self.assertRaises(SystemExit): helper.main()
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
