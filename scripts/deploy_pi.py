#!/usr/bin/env python3
"""Deploy a verified checkout using the Pi's existing project and private config."""
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

DEPLOY_DIR = Path('/opt/private-vault')


def deploy():
    # Keep configuration and the deployment lock outside disposable Jenkins workspaces.
    config = DEPLOY_DIR / '.env.pi'
    if not config.is_file():
        raise RuntimeError('Missing /opt/private-vault/.env.pi; follow deploy/jenkins.md')
    with (DEPLOY_DIR / '.deploy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        if not re.fullmatch(r'[0-9a-f]{40,64}', revision):
            raise RuntimeError('Invalid Git revision')
        env = dict(os.environ, VAULT_API_IMAGE=f'private-vault-api:{revision}',
                   VAULT_PROXY_IMAGE=f'private-vault-proxy:{revision}')
        compose = ['docker', '--context', 'default', 'compose', '--env-file', str(config),
                   '-p', 'private-vault', '-f', 'compose.yaml', '-f', 'deploy/compose.pi.yaml']

        def run(*args, **kwargs):
            return subprocess.run([*compose, *args], env=env, check=True,
                                  timeout=5400, **kwargs)

        resolved = json.loads(run('config', '--format', 'json', capture_output=True,
                                  text=True).stdout)
        origin = urlsplit(resolved['services']['api']['environment']['VAULT_ORIGIN'])
        if origin.scheme != 'https' or not origin.hostname:
            raise RuntimeError('Expected an HTTPS origin')
        address = resolved['services']['proxy']['ports'][0]['host_ip']
        if address in ('0.0.0.0', '::'):
            raise RuntimeError('Refusing wildcard HTTPS publication')
        # Both builds finish before touching running services. Keep previous images.
        run('build', '--pull', 'api', 'proxy')
        run('stop', '--timeout', '30', 'api')
        # Do not automatically roll back binaries across a possibly changed schema.
        run('run', '--rm', '--no-deps', '--pull', 'never', 'api', 'migrate')
        run('up', '--detach', '--no-build', '--pull', 'never', '--wait',
            '--wait-timeout', '90', 'api', 'proxy')
        with tempfile.TemporaryDirectory(prefix='private-vault-health-') as temporary:
            certificate = Path(temporary) / 'root.crt'
            certificate.write_bytes(run('exec', '-T', 'proxy', 'cat',
                '/data/caddy/pki/authorities/local/root.crt', capture_output=True).stdout)
            response = subprocess.run([
                'curl', '--silent', '--show-error', '--fail', '--noproxy', '*',
                '--cacert', str(certificate), '--resolve', f'{origin.hostname}:443:{address}',
                '--connect-timeout', '5', '--max-time', '10', '--retry', '10',
                '--retry-delay', '2', '--retry-connrefused', '--retry-max-time', '60',
                f'https://{origin.hostname}/health'], check=True, capture_output=True,
                text=True, timeout=80)
            if json.loads(response.stdout) != {'status': 'ok'}:
                raise RuntimeError('Unexpected HTTPS health response')
        print(f'Deployed {revision}; verified HTTPS health; existing volumes preserved.')


if __name__ == '__main__':
    deploy()
