import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path

import backup


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="NUU Backup With Spaces ")
        root=Path(self.temp.name)
        backup.DATABASE=root/"data"/"nuu.sqlite3"
        backup.BACKUP_DIR=root/"backups"
        backup.DATABASE.parent.mkdir(parents=True)
        with closing(sqlite3.connect(backup.DATABASE)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE sample (value TEXT)")
            db.execute("INSERT INTO sample VALUES ('before')")
            db.commit()

    def tearDown(self):
        self.temp.cleanup()

    def test_backup_is_consistent_and_restore_keeps_safety_copy(self):
        snapshot=backup.create_backup()
        backup.integrity_check(snapshot)
        with closing(sqlite3.connect(backup.DATABASE)) as db:
            db.execute("UPDATE sample SET value='after'")
            db.commit()
        with self.assertRaises(ValueError):
            backup.restore_backup(snapshot)
        safety=backup.restore_backup(snapshot,confirm=True)
        self.assertTrue(safety and safety.exists())
        with closing(sqlite3.connect(backup.DATABASE)) as db:
            self.assertEqual(db.execute("SELECT value FROM sample").fetchone()[0],"before")

    def test_retention_removes_only_expired_managed_backups(self):
        backup.BACKUP_DIR.mkdir()
        expired=backup.BACKUP_DIR/"nuu-older.sqlite3"
        unrelated=backup.BACKUP_DIR/"do-not-delete.sqlite3"
        expired.touch();unrelated.touch()
        old=(datetime.now(timezone.utc)-timedelta(days=5)).timestamp()
        import os
        os.utime(expired,(old,old));os.utime(unrelated,(old,old))
        backup.create_backup(retention_days=2)
        self.assertFalse(expired.exists())
        self.assertTrue(unrelated.exists())

    def test_integrity_check_rejects_corrupt_backup(self):
        corrupt=backup.BACKUP_DIR/"corrupt.sqlite3"
        corrupt.parent.mkdir(parents=True)
        corrupt.write_bytes(b"not sqlite")
        with self.assertRaises(sqlite3.DatabaseError):
            backup.integrity_check(corrupt)


if __name__=="__main__":
    unittest.main()
