"""Online SQLite backup and guarded restore utilities for NUU."""

from __future__ import annotations

import argparse
import logging
from logging.handlers import RotatingFileHandler
from contextlib import closing
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("NUU_DB_PATH", ROOT / "data" / "nuu.sqlite3"))
BACKUP_DIR = Path(os.environ.get("NUU_BACKUP_DIR", DATABASE.parent / "backups"))
BACKUP_PREFIX = "nuu-"


def integrity_check(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"Database file does not exist: {path}")
    uri_path=quote(str(path.resolve()).replace("\\","/"),safe="/:" )
    with closing(sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True, timeout=30)) as db:
        result = db.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise ValueError(f"SQLite integrity check failed: {result}")


def snapshot(source_path: Path, target_path: Path) -> None:
    """Create a transactionally consistent copy, including committed WAL pages."""
    if not source_path.is_file():
        raise ValueError(f"Database file does not exist: {source_path}")
    integrity_check(source_path)
    if source_path.resolve() == target_path.resolve():
        raise ValueError("Backup destination must differ from the database path.")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".nuu-backup-", suffix=".sqlite3", dir=target_path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        source=sqlite3.connect(source_path,timeout=30)
        destination=sqlite3.connect(temporary,timeout=30)
        try:
            source.backup(destination, pages=256, sleep=0.1)
            destination.execute("PRAGMA journal_mode=DELETE")
            destination.commit()
        finally:
            destination.close()
            source.close()
        integrity_check(temporary)
        os.replace(temporary, target_path)
    finally:
        temporary.unlink(missing_ok=True)


def create_backup(retention_days: int = 30) -> Path:
    if retention_days < 1 or retention_days > 3650:
        raise ValueError("Retention must be between 1 and 3650 days.")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = BACKUP_DIR / f"{BACKUP_PREFIX}{timestamp}.sqlite3"
    snapshot(DATABASE, destination)
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    for candidate in BACKUP_DIR.glob(f"{BACKUP_PREFIX}*.sqlite3"):
        if candidate != destination and datetime.fromtimestamp(candidate.stat().st_mtime, timezone.utc) < cutoff:
            candidate.unlink()
    return destination


def restore_backup(backup_path: Path, confirm: bool = False) -> Path | None:
    if not confirm:
        raise ValueError("Restore is destructive; pass --confirm after stopping the NUU server.")
    backup_path = backup_path.resolve()
    if backup_path == DATABASE.resolve():
        raise ValueError("The live database cannot be used as its own restore source.")
    integrity_check(backup_path)
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    safety_copy = None
    if DATABASE.exists():
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        safety_copy = BACKUP_DIR / f"{BACKUP_PREFIX}pre-restore-{timestamp}.sqlite3"
        snapshot(DATABASE, safety_copy)
    fd, temporary_name = tempfile.mkstemp(prefix=".nuu-restore-", suffix=".sqlite3", dir=DATABASE.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        source=sqlite3.connect(backup_path,timeout=30)
        destination=sqlite3.connect(temporary,timeout=30)
        try:
            source.backup(destination, pages=256, sleep=0.1)
            destination.execute("PRAGMA journal_mode=DELETE")
            destination.commit()
        finally:
            destination.close()
            source.close()
        integrity_check(temporary)
        # Move stale sidecars out of the way before replacing the main file so
        # a previous WAL cannot be replayed into the restored database.
        moved=[]
        try:
            stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            for suffix in ("-wal","-shm","-journal"):
                sidecar=Path(str(DATABASE)+suffix)
                if sidecar.exists():
                    saved=Path(str(sidecar)+f".pre-restore-{stamp}")
                    os.replace(sidecar,saved)
                    moved.append((sidecar,saved))
            os.replace(temporary,DATABASE)
        except Exception:
            for original,saved in reversed(moved):
                if saved.exists():os.replace(saved,original)
            raise
        for _,saved in moved:
            saved.unlink(missing_ok=True)
    finally:
        temporary.unlink(missing_ok=True)
    return safety_copy


def main(argv=None) -> int:
    global DATABASE, BACKUP_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("backup", help="Create a verified online SQLite backup")
    backup.add_argument("--retention-days", type=int, default=30)
    backup.add_argument("--database", type=Path, default=DATABASE)
    backup.add_argument("--backup-dir", type=Path, default=BACKUP_DIR)
    verify = commands.add_parser("verify", help="Check a SQLite backup's integrity")
    verify.add_argument("backup_file", type=Path)
    restore = commands.add_parser("restore", help="Restore a verified backup (stop NUU first)")
    restore.add_argument("backup_file", type=Path)
    restore.add_argument("--confirm", action="store_true", help="Acknowledge the destructive restore")
    args = parser.parse_args(argv)
    if args.command == "backup":
        DATABASE=args.database
        BACKUP_DIR=args.backup_dir
    try:
        BACKUP_DIR.mkdir(parents=True,exist_ok=True)
        handler=RotatingFileHandler(BACKUP_DIR/"backup.log",maxBytes=2*1024*1024,backupCount=3,encoding="utf-8")
        logging.basicConfig(level=logging.INFO,handlers=[handler],format="%(asctime)s %(levelname)s %(message)s")
    except OSError as error:
        print(f"Backup log could not be opened: {error}",file=sys.stderr)
        return 1
    try:
        if args.command == "backup":
            result = create_backup(args.retention_days)
            print(f"Verified NUU backup: {result}")
            logging.info("Backup created and verified: %s",result)
        elif args.command == "verify":
            integrity_check(args.backup_file)
            print(f"SQLite integrity check passed: {args.backup_file.resolve()}")
            logging.info("Backup verified: %s",args.backup_file.resolve())
        else:
            safety_copy = restore_backup(args.backup_file, args.confirm)
            print(f"Restored NUU database from: {args.backup_file.resolve()}")
            if safety_copy:
                print(f"Pre-restore safety copy: {safety_copy}")
            logging.warning("Database restored from %s; safety copy: %s",args.backup_file.resolve(),safety_copy)
        return 0
    except (OSError, sqlite3.Error, ValueError) as error:
        logging.exception("Backup operation failed")
        print(f"Backup operation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
