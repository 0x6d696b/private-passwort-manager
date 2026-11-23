#!/usr/bin/env python3
"""Validate disposable Docker containers; never operate on the normal Compose project."""
from contextlib import closing
import argparse
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
HOST = "vault.validation.test"


def command(args, *, check=True, capture=False, env=None, input=None):
    result = subprocess.run(args, cwd=ROOT, check=check, env=env, input=input,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    return result


def image_digest(reference):
    command(["docker", "pull", reference])
    digests = json.loads(command(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", reference],
        capture=True).stdout)
    if not digests or "@sha256:" not in digests[0]:
        raise RuntimeError("image has no registry digest: " + reference)
    return digests[0]


def unused_subnet():
    ids = command(["docker", "network", "ls", "--quiet"], capture=True).stdout.decode().split()
    existing = []
    if ids:
        networks = json.loads(command(["docker", "network", "inspect", *ids], capture=True).stdout)
        for network in networks:
            for config in network.get("IPAM", {}).get("Config", []) or []:
                if config.get("Subnet"):
                    existing.append(ipaddress.ip_network(config["Subnet"]))
    for index in range(90, 250):
        subnet = ipaddress.ip_network(f"172.29.{index}.0/29")
        if not any(subnet.overlaps(other) for other in existing if other.version == 4):
            return subnet
    raise RuntimeError("no unused validation subnet found")


class LocalHTTPS(http.client.HTTPSConnection):
    """Connect locally while validating the certificate for the private DNS hostname."""
    def connect(self):
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(connection, server_hostname=self.host)


def request(port, context, path, *, method="GET", origin=None, host=HOST):
    connection = LocalHTTPS(HOST, port, context=context, timeout=5)
    headers = {"Host": host}
    if origin:
        headers["Origin"] = origin
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def eventually(operation, seconds=60):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            return operation()
        except (OSError, RuntimeError, subprocess.CalledProcessError, http.client.HTTPException) as error:
            last_error = error
            time.sleep(1)
    raise RuntimeError("container readiness deadline exceeded") from last_error


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_isolation(model, project):
    require(model.get("name") == project, "unexpected Compose project")
    require(set(model["services"]) == {"api", "proxy"}, "unexpected services")
    for section in ("volumes", "networks"):
        for specification in model[section].values():
            require(not specification.get("external"), "external resources are not allowed")
            require(specification.get("name", "").startswith(project + "_"), "resource is outside validation project")
    for service in model["services"].values():
        require("container_name" not in service, "explicit container names are not allowed")
        for mount in service.get("volumes", []):
            require(mount.get("type") == "volume" and mount.get("source") in model["volumes"], "only disposable named-volume mounts are allowed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-image", default="rust:1-bookworm")
    parser.add_argument("--runtime-image", default="debian:bookworm-slim")
    parser.add_argument("--caddy-image", default="caddy:2")
    parser.add_argument("--recovery", action="store_true", help="also validate age-encrypted backup and disaster recovery")
    parser.add_argument("--resilience", action="store_true", help="also run bounded HTTPS load and forced API termination checks")
    args = parser.parse_args()
    if args.recovery:
        from recovery_validation import prerequisites
        prerequisites()
    # No mutations until Docker access has been confirmed.
    command(["docker", "info"], capture=True)
    require((ROOT / "client/dist/vendor/sodium.js").is_file(),
            "browser assets missing: run npm ci --ignore-scripts && npm run build in client/ first")
    command(["python3", "scripts/verify_vendor.py"])
    os.umask(0o077)
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "checks": [], "passed": False, "recovery": args.recovery, "resilience": args.resilience}
    project = "vault-validation-" + uuid.uuid4().hex[:12]
    report["project"] = project
    if args.recovery:
        report["age_version"] = command(["age", "--version"], capture=True).stdout.decode().strip()
    report["images"] = {
        "RUST_IMAGE": image_digest(args.rust_image),
        "RUNTIME_IMAGE": image_digest(args.runtime_image),
        "CADDY_IMAGE": image_digest(args.caddy_image),
    }
    print("Resolved image digests:", json.dumps(report["images"], indent=2), flush=True)
    with tempfile.TemporaryDirectory(prefix="vault-container-validation-") as directory:
        temporary = Path(directory)
        env = temporary / "validation.env"
        variables = {**report["images"], "VAULT_HOST": HOST, "VAULT_LAN_IP": "127.0.0.1"}
        env.write_text("\n".join(f"{key}={value}" for key, value in variables.items()) + "\n")
        # Shell exports must not override the isolated host or pinned image selections.
        environment = {**os.environ, **variables}
        model = json.loads(command([
            "docker", "compose", "--env-file", str(env), "--project-name", project,
            "-f", str(ROOT / "compose.yaml"), "config", "--format", "json"
        ], capture=True, env=environment).stdout)
        validate_isolation(model, project)
        # Use an unused loopback port and separate subnet/volumes for this disposable project.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        subnet = unused_subnet()
        model["services"]["proxy"]["ports"] = [{
            "target": 8443, "published": str(port), "host_ip": "127.0.0.1", "protocol": "tcp"
        }]
        model["networks"]["backend"]["ipam"]["config"] = [{"subnet": str(subnet)}]
        for service, offset in (("api", 2), ("proxy", 3)):
            model["services"][service]["networks"]["backend"]["ipv4_address"] = str(subnet[offset])
        model["services"]["api"]["environment"]["VAULT_BIND"] = f"{subnet[2]}:8080"
        config = temporary / "compose.json"
        config.write_text(json.dumps(model))
        compose = ["docker", "compose", "--project-name", project, "-f", str(config)]

        def run(*args, **options):
            return command([*compose, *args], **options)

        def passed(name):
            report["checks"].append(name)
            print("PASS:", name, flush=True)

        def container(service):
            identifier = run("ps", "--all", "--quiet", service, capture=True).stdout.decode().strip()
            require(bool(identifier), "container missing: " + service)
            return json.loads(command(["docker", "inspect", identifier], capture=True).stdout)[0]

        try:
            run("build", "api", "proxy")
            passed("both images build from digest-pinned bases")
            run("run", "--rm", "--no-deps", "api", "migrate")
            run("run", "--rm", "--no-deps", "api", "init", "--token-file", "/data/enrollment.token")
            passed("migration and account provisioning as non-root")
            run("run", "--rm", "--no-deps", "proxy", "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
            passed("Caddy configuration validates as non-root on fresh volumes")
            run("up", "--detach")

            def certificate():
                result = run("exec", "-T", "proxy", "cat", "/data/caddy/pki/authorities/local/root.crt", capture=True)
                require(b"BEGIN CERTIFICATE" in result.stdout, "CA certificate not ready")
                return result.stdout.decode()

            ca = eventually(certificate)
            context = ssl.create_default_context(cadata=ca)

            def healthy():
                status, _, body = request(port, context, "/health")
                require(status == 200 and json.loads(body) == {"status": "ok"}, "health request failed")

            eventually(healthy)
            passed("trusted HTTPS certificate, hostname verification, and proxy health routing")
            status, headers, body = request(port, context, "/")
            require(status == 200 and b"Private Vault" in body, "browser entry point missing")
            require(headers.get("cache-control") == "no-store", "browser assets must not be cached")
            policy = headers.get("content-security-policy", "")
            require("frame-ancestors 'none'" in policy and "'unsafe-inline'" not in policy,
                    "browser content security policy missing or weakened")
            for path in ("/app.mjs", "/worker.js", "/crypto.mjs", "/vendor/sodium.js", "/vendor/sodium-core.js"):
                status, _, body = request(port, context, path)
                require(status == 200 and bool(body), "browser dependency missing: " + path)
            passed("same-origin browser assets, no-store, and restrictive CSP")
            status, headers, _ = request(port, context, "/api/v1/vault")
            require(status == 401, "anonymous vault access was not rejected")
            require(headers.get("cache-control") == "no-store", "missing no-store header")
            require("max-age=" in headers.get("strict-transport-security", ""), "missing HSTS")
            passed("HTTPS rejects anonymous vault access and sends security headers")
            status, _, _ = request(port, context, "/api/v1/auth/login/begin", method="POST", origin="https://untrusted.test")
            require(status == 403, "cross-origin mutation was not rejected")
            passed("cross-origin mutation rejected through reverse proxy")

            for service in ("api", "proxy"):
                inspected = container(service)
                require(inspected["Config"]["User"] == "10001:10001", "wrong container user")
                host = inspected["HostConfig"]
                require(host["ReadonlyRootfs"], "root filesystem is writable")
                require("ALL" in host["CapDrop"], "capabilities not dropped")
                require(any(option.startswith("no-new-privileges") for option in host["SecurityOpt"]), "privilege escalation not disabled")
                require(host["Memory"] > 0 and host["PidsLimit"] > 0, "resource limits missing")
                if service == "api":
                    require(not any(inspected["NetworkSettings"].get("Ports", {}).values()), "API port is published")
                else:
                    ports = inspected["NetworkSettings"].get("Ports", {})
                    bindings = ports.get("8443/tcp", [])
                    require(bool(bindings) and all(item["HostIp"] == "127.0.0.1" and item["HostPort"] == str(port) for item in bindings), "proxy is not bound to the validation loopback port")
                    require(not any(value for key, value in ports.items() if key != "8443/tcp"), "unexpected published proxy port")
                require(not any("docker.sock" in mount["Destination"] for mount in inspected["Mounts"]), "Docker socket mounted")
            passed("non-root identities, read-only roots, dropped capabilities, limits, private API")
            permissions = """import os, stat
from pathlib import Path
for value, mode in [('/data', 0o700), ('/data/vault.sqlite', 0o600), ('/data/enrollment.token', 0o600)]:
    item = Path(value).stat()
    assert item.st_uid == 10001 and stat.S_IMODE(item.st_mode) == mode
assert os.getuid() == 10001
"""
            run("exec", "-T", "api", "python3", "-c", permissions)
            passed("database and enrollment file ownership and permissions")
            if args.recovery or args.resilience:
                from recovery_validation import SEED_FIXTURE
                run("exec", "-T", "api", "python3", "-c", SEED_FIXTURE)
                passed("synthetic vault entries and a deletion tombstone prepared")
            backup = run("exec", "-T", "api", "python3", "/app/scripts/snapshot.py", "/data/vault.sqlite", capture=True).stdout
            snapshot = temporary / "snapshot.sqlite"
            snapshot.write_bytes(backup)
            del backup
            with closing(sqlite3.connect(snapshot)) as database:
                require(database.execute("PRAGMA integrity_check").fetchone() == ("ok",), "snapshot integrity failed")
                require(database.execute("SELECT count(*) FROM accounts").fetchone() == (1,), "snapshot account missing")
            passed("consistent snapshot runs inside hardened API container")
            if args.recovery:
                from recovery_validation import restore_container
                restore_container(command, run, model, config, project, temporary, snapshot, passed, validate_isolation, lambda: eventually(healthy))
                eventually(healthy)
                restored_status, _, _ = request(port, context, "/api/v1/vault")
                require(restored_status == 401, "restored vault allows unauthenticated access")
                passed("restored API serves trusted HTTPS and still requires authentication")
            if args.resilience:
                from runtime_resilience import exercise
                report["load"] = exercise(run, port, context, request, lambda: eventually(healthy), temporary, passed)
            run("restart", "api")
            eventually(healthy)
            passed("API restarts and reopens existing persistent database")
            report["passed"] = True
        except Exception as error:
            report["error"] = str(error)
            report["cause"] = repr(error.__cause__)
            # Capture only this disposable project's diagnostics before removing it.
            diagnostics = {}
            for service in ("api", "proxy"):
                try:
                    item = container(service)
                    diagnostics[service] = {
                        "state": item["State"],
                        "ports": item["NetworkSettings"].get("Ports"),
                        "networks": list(item["NetworkSettings"].get("Networks", {})),
                    }
                except Exception as inspection_error:
                    diagnostics[service] = {"inspection_error": str(inspection_error)}
            try:
                logs = run("logs", "--no-color", "--tail", "100", capture=True, check=False)
                diagnostics["logs"] = (logs.stdout + logs.stderr).decode(errors="replace")[-20000:]
                probe = run("exec", "-T", "api", "python3", "-c",
                            "import socket; socket.create_connection(('proxy', 8443), timeout=3).close()",
                            capture=True, check=False)
                diagnostics["internal_proxy_tcp"] = {
                    "returncode": probe.returncode,
                    "output": (probe.stdout + probe.stderr).decode(errors="replace")[-2000:],
                }
            except Exception as diagnostic_error:
                diagnostics["capture_error"] = str(diagnostic_error)
            report["diagnostics"] = diagnostics
            raise
        finally:
            # Only this random validation project and its disposable volumes are removed.
            cleanup = run("down", "--volumes", "--remove-orphans", check=False)
            report["cleanup_succeeded"] = cleanup.returncode == 0
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            results = ROOT / ".validation"
            results.mkdir(mode=0o700, exist_ok=True)
            if args.resilience:
                (results / "resilience-latest.json").write_text(json.dumps(report, indent=2) + "\n")
            if args.recovery:
                (results / "recovery-latest.json").write_text(json.dumps(report, indent=2) + "\n")
            (results / "containers-latest.json").write_text(json.dumps(report, indent=2) + "\n")
    require(report["cleanup_succeeded"], "validation project cleanup failed; see report")
    print("Container validation passed. Report: .validation/containers-latest.json")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit("Container validation failed: " + str(error)) from error
