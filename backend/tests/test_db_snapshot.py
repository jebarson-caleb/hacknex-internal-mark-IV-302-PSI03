import importlib.util
import sqlite3
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "db_snapshot.py"
spec = importlib.util.spec_from_file_location("db_snapshot", SCRIPT)
db_snapshot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(db_snapshot)


def _database(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));")
        conn.execute("INSERT INTO parent VALUES(1)")
        conn.execute("INSERT INTO child VALUES(1)")


def test_sqlite_snapshot_and_restore_are_consistent_and_no_overwrite(tmp_path):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "nested" / "snapshot.sqlite3"
    restored = tmp_path / "restored.sqlite3"
    _database(source)
    db_snapshot._copy(source, backup)
    db_snapshot._copy(backup, restored)
    with sqlite3.connect(restored) as conn:
        assert conn.execute("SELECT count(*) FROM child").fetchone()[0] == 1
        db_snapshot._validate(conn)
    with pytest.raises(FileExistsError):
        db_snapshot._copy(source, backup)
    with pytest.raises(ValueError):
        db_snapshot._copy(source, source)


def test_sqlite_snapshot_rejects_corrupt_or_referentially_invalid_source(tmp_path):
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(sqlite3.DatabaseError):
        db_snapshot._copy(corrupt, tmp_path / "bad-copy.sqlite3")
    invalid = tmp_path / "invalid.sqlite3"
    _database(invalid)
    with sqlite3.connect(invalid) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("INSERT INTO child VALUES(99)")
    with pytest.raises(RuntimeError, match="foreign key"):
        db_snapshot._copy(invalid, tmp_path / "invalid-copy.sqlite3")
