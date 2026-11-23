"""Disposable encrypted-backup recovery checks shared by the Docker drill and tests."""
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess

from collect import compare, inspect_snapshot, save_checkpoint
from verify_restore import verify


def prerequisites():
    missing = [name for name in ("age", "age-keygen") if not shutil.which(name)]
    if missing:
        raise RuntimeError("Recovery validation requires age and age-keygen; install age first")


def keypair(path):
    # stdout/stderr are captured; the identity file must never enter logs or reports.
    subprocess.run(["age-keygen", "-o", str(path)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    os.chmod(path, 0o600)
    recipient = subprocess.run(["age-keygen", "-y", str(path)], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout.decode().strip()
    if not recipient.startswith("age1"):
        raise RuntimeError("unexpected age recipient")
    return recipient


def decrypt(backup, identity, output):
    """Do not retain partial plaintext when authenticated decryption fails."""
    # Exclusive creation prevents accidental replacement of any existing candidate.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            subprocess.run(["age", "--decrypt", "--identity", str(identity), str(backup)],
                           stdout=stream, stderr=subprocess.PIPE, check=True, timeout=60)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        Path(output).unlink(missing_ok=True)
        raise


def expect_decryption_failure(backup, identity, output):
    try:
        decrypt(backup, identity, output)
    except subprocess.CalledProcessError:
        if Path(output).exists():
            raise RuntimeError("failed decryption left a plaintext candidate")
    else:
        raise RuntimeError("invalid recovery input was accepted")


def create_archive(snapshot, directory, passed):
    prerequisites()
    archive = directory / "archive"
    archive.mkdir(mode=0o700)
    keys = directory / "offline-test-keys"
    keys.mkdir(mode=0o700)
    identity = keys / "recovery.key"
    recipient = keypair(identity)
    wrong_identity = keys / "wrong.key"
    keypair(wrong_identity)
    current = inspect_snapshot(snapshot)
    compare({"format": 1, "sequence": 0, "events": [], "state_sha256": current["state_sha256"]}, current)
    checkpoint = save_checkpoint(archive, snapshot, current, recipient)
    expected = json.loads(checkpoint.read_text())
    encrypted = archive / expected["backup_file"]
    if encrypted.read_bytes().startswith(b"SQLite format 3"):
        raise RuntimeError("backup was not encrypted")
    if stat.S_IMODE(identity.stat().st_mode) != 0o600:
        raise RuntimeError("recovery identity permissions are unsafe")
    passed("collector encrypts a consistent snapshot with an independent checkpoint")

    expect_decryption_failure(encrypted, wrong_identity, directory / "wrong-key.sqlite")
    ciphertext = bytearray(encrypted.read_bytes())
    ciphertext[-1] ^= 1
    corrupted = directory / "corrupted.age"
    corrupted.write_bytes(ciphertext)
    expect_decryption_failure(corrupted, identity, directory / "corrupted.sqlite")
    truncated = directory / "truncated.age"
    truncated.write_bytes(encrypted.read_bytes()[:len(ciphertext) // 2])
    expect_decryption_failure(truncated, identity, directory / "truncated.sqlite")
    passed("wrong recovery key, modified ciphertext, and truncated backup are rejected")

    candidate = directory / "candidate.sqlite"
    decrypt(encrypted, identity, candidate)
    verify(candidate, checkpoint)
    changed = dict(expected, state_sha256="0" * 64)
    mismatched = directory / "mismatched.checkpoint.json"
    mismatched.write_text(json.dumps(changed))
    try:
        verify(candidate, mismatched)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("mismatched independent checkpoint was accepted")
    # Also detect a structurally valid SQLite file with altered vault state.
    tampered = directory / "tampered.sqlite"
    shutil.copyfile(candidate, tampered)
    with closing(sqlite3.connect(tampered)) as connection, connection:
        connection.execute("UPDATE accounts SET enrollment_hash='tampered', enrollment_expires=1")
    try:
        verify(tampered, checkpoint)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("modified restored state was accepted")
    passed("checkpoint verification accepts the exact restore and rejects altered state")
    candidate.unlink()
    tampered.unlink()
    return encrypted, identity, checkpoint


# Opaque synthetic records test persistence, not future client cryptography.
SEED_FIXTURE = r'''
import base64, json, os, sqlite3, time, uuid
from contextlib import closing
encode = lambda size: base64.urlsafe_b64encode(os.urandom(size)).decode().rstrip('=')
with closing(sqlite3.connect('/data/vault.sqlite')) as db, db:
    db.execute('PRAGMA foreign_keys=ON')
    owner = db.execute('SELECT id FROM accounts').fetchone()[0]
    vault = str(uuid.uuid4())
    entry = str(uuid.uuid4())
    deleted = str(uuid.uuid4())
    envelope = json.dumps({'version':1,'salt':encode(16),'nonce':encode(24),'wrapped_key':encode(48),
        'kdf':{'algorithm':'argon2id','version':19,'memory_kib':65536,'iterations':3,'parallelism':1}})
    db.execute('INSERT INTO vaults(id,owner,envelope,revision,sequence) VALUES (?,?,?,1,0)',(vault,owner,envelope))
    db.execute('INSERT INTO entries(id,vault,owner,ciphertext,nonce,revision,deleted,updated_at) VALUES (?,?,?,?,?,3,0,?)',
        (entry,vault,owner,encode(64),encode(24),int(time.time())))
    db.execute("INSERT INTO entries(id,vault,owner,ciphertext,nonce,revision,deleted,updated_at) VALUES (?,?,?,'',?,2,1,?)",
        (deleted,vault,owner,encode(24),int(time.time())))
    for operation, subject, revision in [('vault.put',vault,1),('entry.put',entry,3),('entry.delete',deleted,2)]:
        db.execute('INSERT INTO audit_outbox(event_id,operation,subject,revision,created_at) VALUES (?,?,?,?,?)',
            (str(uuid.uuid4()),operation,subject,revision,int(time.time())))
    sequence = db.execute('SELECT max(sequence) FROM audit_outbox').fetchone()[0]
    db.execute('UPDATE vaults SET sequence=? WHERE id=?',(sequence,vault))
'''

INSTALL_VERIFIED = r'''
import os, sys
from pathlib import Path
assert os.getuid() == 10001
assert not list(Path('/data').glob('vault.sqlite*')), 'restore target is not empty'
payload = sys.stdin.buffer.read(128 * 1024 * 1024 + 1)
assert len(payload) <= 128 * 1024 * 1024
assert payload.startswith(b'SQLite format 3' + bytes([0]))
fd = os.open('/data/vault.sqlite', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd,'wb') as output:
    output.write(payload)
    output.flush()
    os.fsync(output.fileno())
'''


def destroy_source_volume(command, run, name, project):
    """Destruction is restricted to the named volume of this disposable project."""
    if not project.startswith("vault-validation-") or name != project + "_vault_data":
        raise RuntimeError("refusing to remove a volume outside the recovery fixture")
    metadata = json.loads(command(["docker", "volume", "inspect", name], capture=True).stdout)[0]
    labels = metadata.get("Labels") or {}
    if labels.get("com.docker.compose.project") != project or labels.get("com.docker.compose.volume") != "vault_data":
        raise RuntimeError("source volume ownership does not match validation project")
    run("stop", "api")
    run("rm", "--force", "api")
    command(["docker", "volume", "rm", name])


def restore_container(command, run, model, config, project, directory, snapshot, passed, validate_isolation, ready):
    encrypted, identity, checkpoint = create_archive(snapshot, directory, passed)
    source_name = model["volumes"]["vault_data"]["name"]
    destroy_source_volume(command, run, source_name, project)
    snapshot.unlink()  # No unencrypted source snapshot remains as a recovery fallback.
    passed("original disposable API container, source volume, and snapshot removed")

    restored = directory / "recovered.sqlite"
    decrypt(encrypted, identity, restored)
    verify(restored, checkpoint)  # Never install or start an unverified candidate.
    passed("database recovered using only the encrypted backup, identity, and checkpoint")

    model["volumes"]["restore_data"] = {"name": project + "_restore_data"}
    mounts = model["services"]["api"]["volumes"]
    if len(mounts) != 1 or mounts[0].get("source") != "vault_data":
        raise RuntimeError("unexpected source volume mapping")
    mounts[0]["source"] = "restore_data"
    validate_isolation(model, project)
    config.write_text(json.dumps(model))
    run("run", "--rm", "--no-deps", "-T", "--entrypoint", "python3", "api", "-c", INSTALL_VERIFIED,
        input=restored.read_bytes())
    restored.unlink()
    run("up", "--detach", "--no-deps", "api")
    ready()
    # Snapshot the restored live database, not the previous plaintext file.
    raw = run("exec", "-T", "api", "python3", "/app/scripts/snapshot.py", "/data/vault.sqlite", capture=True).stdout
    actual = directory / "live-restored.sqlite"
    actual.write_bytes(raw)
    current = inspect_snapshot(actual)
    expected = json.loads(checkpoint.read_text())
    for field in ("format", "sequence", "state_sha256", "events"):
        if json.dumps(current[field]) != json.dumps(expected[field]):
            raise RuntimeError("restored container changed saved vault state: " + field)
    with closing(sqlite3.connect(actual)) as database:
        if database.execute('SELECT count(*) FROM entries WHERE deleted=0').fetchone()[0] != 1:
            raise RuntimeError("restored active entry is missing")
        if database.execute('SELECT count(*) FROM entries WHERE deleted=1').fetchone()[0] != 1:
            raise RuntimeError("restored deletion tombstone is missing")
    passed("fresh container preserves ciphertext, envelope, revisions, tombstones, and audit history")
