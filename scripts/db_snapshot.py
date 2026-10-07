"""Create or restore a consistent, validated SQLite snapshot without overwrite."""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from urllib.parse import quote


def _validate(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {result[0] if result else 'no result'}")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"SQLite foreign key check found {len(violations)} violation(s)")


def _copy(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    destination = destination.resolve(strict=False)
    if source == destination:
        raise ValueError("source and destination must be different files")
    if not source.is_file():
        raise ValueError("source must be a regular SQLite file")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing destination: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create prevents clobbering a file created after the existence check.
    with destination.open("xb"):
        pass
    try:
        source_uri = f"file:{quote(source.as_posix(), safe='/:')}?mode=ro"
        with sqlite3.connect(source_uri, uri=True, timeout=30) as src:
            _validate(src)
            with sqlite3.connect(destination, timeout=30) as dst:
                src.backup(dst, pages=256, sleep=0.05)
                _validate(dst)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    snapshot = sub.add_parser("snapshot", help="create a consistent new backup")
    snapshot.add_argument("database", type=Path)
    snapshot.add_argument("destination", type=Path)
    restore = sub.add_parser("restore", help="restore a validated snapshot to a new file")
    restore.add_argument("snapshot", type=Path)
    restore.add_argument("destination", type=Path)
    args = parser.parse_args()
    source = args.database if args.operation == "snapshot" else args.snapshot
    _copy(source, args.destination)
    print(f"{args.operation} complete: {source.resolve()} -> {args.destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
