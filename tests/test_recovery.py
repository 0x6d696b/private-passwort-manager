"""Real age integration checks and safety guards for the disposable recovery drill."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import recovery_validation as recovery
from collect import inspect_snapshot
from verify_restore import verify


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.database = self.root / "snapshot.sqlite"
        with closing(sqlite3.connect(self.database)) as database, database:
            database.executescript((ROOT / "migrations/0001_initial.sql").read_text())
            database.execute("INSERT INTO accounts(id) VALUES ('test-owner')")
            database.execute("INSERT INTO audit_outbox(event_id,operation,subject,created_at) VALUES ('event-1','account.init','test-owner',1)")
        # Execute the same trusted fixture code the disposable container will run.
        fixture = recovery.SEED_FIXTURE.replace("'/data/vault.sqlite'", repr(str(self.database)))
        exec(compile(fixture, "recovery-fixture", "exec"), {})

    def test_real_age_backup_survives_loss_of_plaintext_and_rejects_tampering(self):
        # An explicit dependency: fail with an installation instruction if age is absent.
        recovery.prerequisites()
        checks = []
        encrypted, identity, checkpoint = recovery.create_archive(self.database, self.root, checks.append)
        expected = inspect_snapshot(self.database)
        self.database.unlink()
        restored = self.root / "restored.sqlite"
        recovery.decrypt(encrypted, identity, restored)
        verify(restored, checkpoint)
        self.assertEqual(inspect_snapshot(restored), expected)
        with closing(sqlite3.connect(restored)) as database:
            self.assertEqual(database.execute("SELECT count(*) FROM entries WHERE deleted=0").fetchone()[0], 1)
            self.assertEqual(database.execute("SELECT count(*) FROM entries WHERE deleted=1").fetchone()[0], 1)
        self.assertEqual(len(checks), 3)
        self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)

    def test_partial_plaintext_is_removed_after_decryption_failure(self):
        output = self.root / "partial.sqlite"

        def fail(*args, **kwargs):
            kwargs["stdout"].write(b"partial unauthenticated plaintext")
            raise subprocess.CalledProcessError(1, args[0])

        with patch.object(recovery.subprocess, "run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                recovery.decrypt(self.root / "backup.age", self.root / "identity", output)
        self.assertFalse(output.exists())

    def test_decryption_cannot_overwrite_an_existing_file(self):
        output = self.root / "existing.sqlite"
        output.write_bytes(b"keep me")
        with self.assertRaises(FileExistsError):
            recovery.decrypt(self.root / "backup.age", self.root / "identity", output)
        self.assertEqual(output.read_bytes(), b"keep me")

    def test_source_volume_deletion_requires_matching_name_and_labels(self):
        executed = []

        def command(args, **kwargs):
            executed.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps([{"Labels": {
                "com.docker.compose.project": "production",
                "com.docker.compose.volume": "vault_data"
            }}]).encode())

        def run(*args, **kwargs):
            raise AssertionError("must not stop or delete containers for an unverified volume")

        with self.assertRaises(RuntimeError):
            recovery.destroy_source_volume(command, run, "production_vault_data", "vault-validation-test")
        self.assertEqual(executed, [])
        with self.assertRaises(RuntimeError):
            recovery.destroy_source_volume(command, run, "vault-validation-test_vault_data", "vault-validation-test")
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0][0:3], ["docker", "volume", "inspect"])

    def test_restore_installer_refuses_existing_database_and_wal(self):
        # Exercise the exact container installer against a temporary path, never /data.
        target = self.root / "target"
        target.mkdir()
        code = recovery.INSTALL_VERIFIED.replace("'/data'", repr(str(target))).replace("'/data/vault.sqlite'", repr(str(target / 'vault.sqlite')))
        code = code.replace("assert os.getuid() == 10001", "assert os.getuid() == " + str(os.getuid()))
        payload = self.database.read_bytes()
        (target / "vault.sqlite-wal").write_bytes(b"old WAL must block restoration")
        blocked = subprocess.run([sys.executable, "-c", code], input=payload, capture_output=True)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertFalse((target / "vault.sqlite").exists())
        (target / "vault.sqlite-wal").unlink()
        subprocess.run([sys.executable, "-c", code], input=payload, check=True, capture_output=True)
        self.assertEqual((target / "vault.sqlite").read_bytes(), payload)
        self.assertEqual(stat.S_IMODE((target / "vault.sqlite").stat().st_mode), 0o600)
        blocked = subprocess.run([sys.executable, "-c", code], input=payload, capture_output=True)
        self.assertNotEqual(blocked.returncode, 0)


if __name__ == "__main__":
    unittest.main()
