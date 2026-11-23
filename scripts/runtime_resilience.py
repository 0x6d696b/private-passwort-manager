"""Bounded HTTPS overload and abrupt-container-restart checks for disposable fixtures."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import math
import time

from collect import inspect_snapshot


def summarize(results, elapsed):
    statuses = Counter(status for status, _ in results)
    if not results or not set(statuses).issubset({401, 429, 503}):
        raise RuntimeError("protected endpoint returned an unexpected status under anonymous load")
    if not statuses[429]:
        raise RuntimeError("load did not exercise the request rate limit")
    times = sorted(duration for _, duration in results)
    return {
        "requests": len(results), "concurrency": 16,
        "status_counts": dict(statuses), "elapsed_seconds": round(elapsed, 4),
        "p50_seconds": round(times[math.ceil(len(times) * 0.50) - 1], 4),
        "p95_seconds": round(times[math.ceil(len(times) * 0.95) - 1], 4),
        "max_seconds": round(times[-1], 4),
        "scope": "anonymous protected-endpoint requests including TLS setup; not a throughput SLO",
    }


def exercise(run, port, context, request, ready, directory, passed):
    def snapshot(name):
        output = run("exec", "-T", "api", "python3", "/app/scripts/snapshot.py", "/data/vault.sqlite", capture=True).stdout
        path = directory / name
        path.write_bytes(output)
        return inspect_snapshot(path)

    before = snapshot("before-load.sqlite")

    def attempt(_):
        start = time.monotonic()
        status, _, _ = request(port, context, "/api/v1/vault")
        return status, time.monotonic() - start

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(attempt, number) for number in range(300)]
        # Health must remain reachable while business requests are in flight.
        for _ in range(10):
            status, _, payload = request(port, context, "/health")
            if status != 200 or json.loads(payload) != {"status": "ok"}:
                raise RuntimeError("health became unavailable during load")
        results = [future.result() for future in futures]  # Transport errors are failures.
    measurements = summarize(results, time.monotonic() - started)
    passed("300 anonymous HTTPS requests stay unauthorized, throttle, and preserve health access")
    for _ in range(16):
        status, _, _ = request(port, context, "/api/v1/auth/login/begin", method="POST", origin="https://untrusted.test")
        if status != 403:
            raise RuntimeError("origin protection changed under request exhaustion")
    if snapshot("after-load.sqlite") != before:
        raise RuntimeError("anonymous overload mutated persistent vault or audit state")
    passed("origin rejection and persistent state remain intact after overload")

    run("kill", "--signal", "SIGKILL", "api")
    run("up", "--detach", "--no-deps", "api")
    ready()
    status, _, _ = request(port, context, "/api/v1/vault")
    if status != 401:
        raise RuntimeError("authentication or request capacity did not recover after process restart")
    after = snapshot("after-kill.sqlite")
    if json.dumps(after, sort_keys=True) != json.dumps(before, sort_keys=True):
        raise RuntimeError("committed state changed after forced API termination")
    passed("SIGKILL and API restart preserve committed data and restore request capacity")
    return measurements
