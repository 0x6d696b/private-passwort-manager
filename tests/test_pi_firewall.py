"""Exercise the real shell installer logic against an isolated iptables model."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE = r'''
import json, os, sys
from pathlib import Path
path = Path(os.environ['PV_FIREWALL_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]
assert args[:2] == ['-w','5']
op, chain, *rule = args[2:]
if op == '-N':
    if chain in state: raise SystemExit(1)
    state[chain] = []
elif op == '-L':
    if chain not in state: raise SystemExit(1)
elif op == '-C':
    raise SystemExit(0 if rule in state.get(chain,[]) else 1)
elif op == '-F': state[chain] = []
elif op == '-X': del state[chain]
elif op == '-A':
    if os.environ.get('PV_FAIL_APPEND') and chain == 'PV_PI_HTTPS': raise SystemExit(1)
    state[chain].append(rule)
elif op == '-D': state[chain].remove(rule)
elif op == '-I':
    index = int(rule.pop(0))-1 if rule and rule[0].isdigit() else 0
    state[chain].insert(index,rule)
else: raise AssertionError(args)
path.write_text(json.dumps(state))
'''


class PiFirewallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.state = root / 'rules.json'
        self.original = {
            'INPUT': [['-p', 'tcp', '--dport', '22', '-j', 'ACCEPT']],
            'FORWARD': [['-j', 'DOCKER-USER'], ['-j', 'DOCKER-FORWARD']],
            'DOCKER-USER': [['-s', '198.51.100.1', '-j', 'RETURN']],
            'DOCKER': [['-p', 'tcp', '--dport', '8080', '-j', 'ACCEPT']],
        }
        self.state.write_text(json.dumps(self.original))
        executable = root / 'iptables'
        executable.write_text('#!' + sys.executable + '\n' + FAKE)
        executable.chmod(0o700)
        self.environment = {**os.environ, 'PV_IPTABLES': str(executable), 'PV_FIREWALL_STATE': str(self.state),
                            'PV_FIREWALL_CONFIG': str(root/'absent.conf'),
                            'PV_LAN_IP': '192.168.50.10', 'PV_LAN_CIDR': '192.168.50.0/24',
                            'PV_LAN_INTERFACE': 'eth0'}

    def apply(self, operation='apply', check=True, extra=None):
        return subprocess.run(['sh', str(ROOT/'deploy/pi-firewall.sh'), operation],
                              env={**self.environment, **(extra or {})}, check=check, capture_output=True)

    def read(self):
        return json.loads(self.state.read_text())

    def test_scoped_policy_preserves_ssh_other_ports_and_existing_rules(self):
        self.apply()
        rules = self.read()
        for name in ['INPUT', 'FORWARD', 'DOCKER']:
            self.assertEqual(rules[name], self.original[name])
        hook = rules['DOCKER-USER'][0]
        self.assertIn('--ctorigdst', hook)
        self.assertEqual(hook[hook.index('--ctorigdst')+1], '192.168.50.10')
        self.assertEqual(hook[hook.index('--ctorigdstport')+1], '443')
        self.assertEqual(hook[hook.index('--ctdir')+1], 'ORIGINAL')
        self.assertEqual(rules['DOCKER-USER'][1:], self.original['DOCKER-USER'])
        self.assertEqual(rules['PV_PI_HTTPS'], [
            ['-i','eth0','-s','192.168.50.0/24','-j','RETURN'], ['-j','DROP']])

    def test_missing_host_settings_fail_before_changing_rules(self):
        environment = dict(self.environment)
        environment.pop('PV_LAN_IP')
        result = subprocess.run(['sh', str(ROOT/'deploy/pi-firewall.sh')],
                                env=environment, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read(), self.original)

    def test_explicit_local_profile_controls_address_and_source(self):
        self.apply(extra={'PV_LAN_IP':'10.20.30.10', 'PV_LAN_CIDR':'10.20.30.0/24', 'PV_LAN_INTERFACE':'enp1s0'})
        rules = self.read()
        self.assertIn('10.20.30.10', rules['DOCKER-USER'][0])
        self.assertEqual(rules['PV_PI_HTTPS'][0], ['-i','enp1s0','-s','10.20.30.0/24','-j','RETURN'])

    def test_reapplying_is_idempotent_and_removal_is_scoped(self):
        self.apply()
        initial = self.read()
        self.apply()
        self.assertEqual(self.read(), initial)
        self.apply('remove')
        self.assertEqual(self.read(), self.original)

    def test_bootstrap_installs_hook_before_docker_has_created_it(self):
        self.state.write_text(json.dumps({'INPUT': [], 'FORWARD': [], 'DOCKER': []}))
        self.apply()
        self.assertEqual(self.read()['FORWARD'], [['-j','DOCKER-USER']])
        self.assertEqual(self.read()['DOCKER-USER'][0][-1], 'PV_PI_HTTPS')

    def test_failed_update_keeps_scoped_drop_guard_first(self):
        self.apply()
        result = self.apply(check=False, extra={'PV_FAIL_APPEND': '1'})
        self.assertNotEqual(result.returncode, 0)
        rules = self.read()
        first = rules['DOCKER-USER'][0]
        self.assertEqual(first[-2:], ['-j','DROP'])
        self.assertIn('private-vault-update', first)
        self.assertEqual(rules['INPUT'], self.original['INPUT'])
        self.assertEqual(rules['DOCKER'], self.original['DOCKER'])

    def test_systemd_orders_guard_before_docker_without_removing_rules_on_stop(self):
        import configparser
        unit = configparser.ConfigParser()
        unit.read(ROOT / 'deploy/private-vault-firewall.service')
        dropin = configparser.ConfigParser()
        dropin.read(ROOT / 'deploy/docker-firewall.conf')
        self.assertIn('docker.service', unit['Unit']['Before'].split())
        self.assertIn('private-vault-firewall.service', dropin['Unit']['Requires'].split())
        self.assertIn('private-vault-firewall.service', dropin['Unit']['After'].split())
        self.assertEqual(unit['Service']['RemainAfterExit'], 'yes')
        self.assertNotIn('ExecStop', unit['Service'])


if __name__ == '__main__':
    unittest.main()
