from contextlib import closing
import importlib.util
import io
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

collect = module("collect")
snapshot = module("snapshot")
sys.path.insert(0, str(ROOT / "scripts"))
restore = module("verify_restore")
health = module("check_checkpoint")


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "vault.sqlite"
        self.database = sqlite3.connect(self.path)
        self.addCleanup(self.database.close)
        self.database.execute("PRAGMA foreign_keys = ON")
        self.database.execute("PRAGMA journal_mode = WAL")
        self.database.executescript((ROOT / "migrations/0001_initial.sql").read_text())
        self.database.execute("INSERT INTO accounts(id) VALUES ('owner')")
        self.database.execute("INSERT INTO audit_outbox(event_id,operation,subject,created_at) VALUES ('event-1','account.init','owner',1)")
        self.database.commit()

    def test_online_backup_includes_committed_wal_and_excludes_uncommitted_changes(self):
        self.database.execute("UPDATE accounts SET enrollment_hash = 'uncommitted', enrollment_expires = 9")
        output = io.BytesIO()
        snapshot.snapshot(self.path, output)
        restored = Path(self.directory.name) / "restored.sqlite"
        restored.write_bytes(output.getvalue())
        with closing(sqlite3.connect(restored)) as backup:
            self.assertEqual(backup.execute("SELECT enrollment_hash FROM accounts").fetchone(), (None,))
            self.assertEqual(backup.execute("SELECT count(*) FROM audit_outbox").fetchone(), (1,))
        self.database.rollback()

    def test_same_sequence_modified_state_is_detected(self):
        previous = collect.inspect_snapshot(self.path)
        self.database.execute("UPDATE accounts SET enrollment_hash = 'tampered', enrollment_expires = 1")
        self.database.commit()
        with self.assertRaisesRegex(RuntimeError, "state changed"):
            collect.compare(previous, collect.inspect_snapshot(self.path))

    def test_sequence_regression_is_detected(self):
        old = collect.inspect_snapshot(self.path)
        new = dict(old, sequence=0, events=[])
        with self.assertRaisesRegex(RuntimeError, "regressed"):
            collect.compare(old, new)

    def test_modified_or_missing_archived_event_is_detected(self):
        old = collect.inspect_snapshot(self.path)
        self.database.execute("UPDATE audit_outbox SET subject = 'changed'")
        self.database.commit()
        with self.assertRaisesRegex(RuntimeError, "event missing or modified"):
            collect.compare(old, collect.inspect_snapshot(self.path))

    def test_legitimate_new_event_is_accepted(self):
        old = collect.inspect_snapshot(self.path)
        self.database.execute("INSERT INTO audit_outbox(event_id,operation,subject,created_at) VALUES ('event-2','session.login','owner',2)")
        self.database.commit()
        collect.compare(old, collect.inspect_snapshot(self.path))

    def test_json_checkpoint_accepts_unchanged_snapshot(self):
        previous = json.loads(json.dumps(collect.inspect_snapshot(self.path)))
        collect.compare(previous, collect.inspect_snapshot(self.path))

    def test_json_checkpoint_accepts_new_event(self):
        previous = json.loads(json.dumps(collect.inspect_snapshot(self.path)))
        self.database.execute("INSERT INTO audit_outbox(event_id,operation,subject,created_at) VALUES ('event-2','session.login','owner',2)")
        self.database.commit()
        collect.compare(previous, collect.inspect_snapshot(self.path))

    def test_json_checkpoint_still_rejects_modified_history(self):
        previous = json.loads(json.dumps(collect.inspect_snapshot(self.path)))
        self.database.execute("UPDATE audit_outbox SET subject = 'modified'")
        self.database.commit()
        with self.assertRaisesRegex(RuntimeError, "event missing or modified"):
            collect.compare(previous, collect.inspect_snapshot(self.path))

    def test_snapshot_transport_is_bounded_and_reports_failed_commands(self):
        with self.assertRaisesRegex(RuntimeError, "command failed"):
            collect.pull([sys.executable, "-c", "raise SystemExit(1)"], io.BytesIO())
        original = collect.MAX_BYTES
        try:
            collect.MAX_BYTES = 4
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                collect.pull([sys.executable, "-c", "print('too much output')"], io.BytesIO())
        finally:
            collect.MAX_BYTES = original

    def test_huge_sequence_is_rejected_without_unbounded_allocation(self):
        current = collect.inspect_snapshot(self.path)
        with self.assertRaisesRegex(RuntimeError, "invalid audit sequence"):
            collect.compare(current, dict(current, sequence=2**63 - 1))

    def test_restore_matches_archived_checkpoint_and_rejects_changed_file(self):
        target = Path(self.directory.name) / "restore.sqlite"
        output = io.BytesIO()
        snapshot.snapshot(self.path, output)
        target.write_bytes(output.getvalue())
        checkpoint = collect.inspect_snapshot(target)
        checkpoint["snapshot_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        archive = Path(self.directory.name) / "checkpoint.json"
        archive.write_text(json.dumps(checkpoint))
        restore.verify(target, archive)
        with closing(sqlite3.connect(target)) as changed, changed:
            changed.execute("UPDATE accounts SET enrollment_hash='tampered', enrollment_expires=1")
        with self.assertRaisesRegex(RuntimeError, "restore does not match"):
            restore.verify(target, archive)

    def test_independent_monitor_detects_stale_or_missing_backups(self):
        archive = Path(self.directory.name) / "archive"
        archive.mkdir()
        (archive / "latest").write_text("checkpoint.json")
        state = {"collected_at": datetime.now(timezone.utc).isoformat(), "backup_file": "backup.age"}
        checkpoint = archive / "checkpoint.json"
        checkpoint.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "backup is missing"):
            health.check(archive, 900)
        (archive / "backup.age").touch()
        health.check(archive, 900)
        state["collected_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        checkpoint.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "stale"):
            health.check(archive, 900)

    def test_foreign_key_constraint_blocks_cross_owner_entry(self):
        self.database.execute("INSERT INTO vaults(id,owner,envelope,revision,sequence) VALUES ('v','owner','opaque',1,0)")
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.execute("INSERT INTO entries(id,vault,owner,ciphertext,nonce,revision,updated_at) VALUES ('e','v','intruder','opaque',?,1,1)", ("a" * 32,))


if __name__ == "__main__":
    unittest.main()
