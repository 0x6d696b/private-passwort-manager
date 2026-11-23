import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('deploy_pi', Path(__file__).resolve().parents[1] / 'scripts/deploy_pi.py')
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class DeploymentTests(unittest.TestCase):
    def exercise(self, fail=None, address='192.168.50.10'):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if fail and fail in command:
                raise subprocess.CalledProcessError(1, command)
            if '--format' in command:
                output = json.dumps({'services': {
                    'api': {'environment': {'VAULT_ORIGIN': 'https://vault.home.arpa'}},
                    'proxy': {'ports': [{'host_ip': address}]}}})
            elif command[0] == 'curl':
                self.assertIn('--cacert', command)
                self.assertNotIn('-k', command)
                output = '{"status":"ok"}'
            else:
                output = b'certificate'
            return subprocess.CompletedProcess(command, 0, stdout=output)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.pi').write_text('')
            with patch.object(deployment, 'DEPLOY_DIR', root), \
                    patch.object(deployment.subprocess, 'check_output', return_value='a' * 40), \
                    patch.object(deployment.subprocess, 'run', side_effect=run):
                if fail:
                    with self.assertRaises(subprocess.CalledProcessError):
                        deployment.deploy()
                elif address == '0.0.0.0':
                    with self.assertRaises(RuntimeError):
                        deployment.deploy()
                else:
                    deployment.deploy()
        return calls

    def test_build_migrate_restart_and_verified_health_in_order(self):
        calls = self.exercise()
        self.assertEqual([c[12] for c in calls[:-1]], ['config', 'build', 'stop', 'run', 'up', 'exec'])
        self.assertEqual(calls[-1][0], 'curl')
        self.assertTrue(all('down' not in c and '--volumes' not in c for c in calls))

    def test_build_failure_does_not_stop_live_api(self):
        calls = self.exercise(fail='build')
        self.assertFalse(any('stop' in c for c in calls))

    def test_migration_failure_does_not_restart_incompatible_server(self):
        calls = self.exercise(fail='migrate')
        self.assertFalse(any('up' in c for c in calls))

    def test_wildcard_publication_fails_before_build(self):
        self.assertEqual(len(self.exercise(address='0.0.0.0')), 1)

    def test_failed_https_check_fails_deployment(self):
        self.exercise(fail='curl')

    def test_overlapping_deployment_fails_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.pi').write_text('')
            with (root / '.deploy.lock').open('a') as lock:
                deployment.fcntl.flock(lock, deployment.fcntl.LOCK_EX)
                with patch.object(deployment, 'DEPLOY_DIR', root), \
                        patch.object(deployment.subprocess, 'run') as run:
                    with self.assertRaises(BlockingIOError):
                        deployment.deploy()
                    run.assert_not_called()
