"""Build an allowlisted local submission copy and fail on common privacy leaks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from datetime import datetime, timezone


_separator = re.escape("\\")
_windows_home = r"[A-Z]:" + _separator + "Users" + _separator + r"[^\s<>\"']+"
PRIVATE_PATH = re.compile(r"(?i)(?:" + _windows_home + r"|[A-Z]:/Users/[^\s<>\"']+|<LOCAL_PATH_REDACTED><>\"']*)")
SECRET = re.compile(r"(?:-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{30,}\b|\bxox[baprs]-[A-Za-z0-9-]{20,}\b)")
FORBIDDEN_PARTS = {".git", ".venv", "node_modules", "runtime", "__pycache__", ".pytest_cache",
    "test-results", "playwright-report", "dist"}
FORBIDDEN_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".log", ".evtx", ".exe", ".dll", ".so",
    ".pyd", ".whl", ".zip", ".gz", ".tar", ".node", ".bin", ".png", ".jpg", ".jpeg", ".pdf"}


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _review(folder: Path):
    errors = []
    files = sorted(path for path in folder.rglob("*") if path.is_file())
    for path in files:
        parts = {part.lower() for part in path.relative_to(folder).parts}
        if parts & FORBIDDEN_PARTS:
            errors.append(f"generated/cache path included: {path.relative_to(folder)}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"runtime/raw/binary artifact type included: {path.relative_to(folder)}")
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PRIVATE_PATH.search(content):
            errors.append(f"private machine path in text: {path.relative_to(folder)}")
        if SECRET.search(content):
            errors.append(f"credential-like value in text: {path.relative_to(folder)}")
    return files, errors


def _redact_private_paths(folder: Path) -> int:
    changed = 0
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        sanitized, count = PRIVATE_PATH.subn("<LOCAL_PATH_REDACTED>", content)
        if count:
            path.write_text(sanitized, encoding="utf-8", newline="\n")
            changed += count
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("submission/traceguard-final-release"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    target = args.output.resolve()
    if target.exists():
        parser.error(f"refusing to overwrite existing submission directory: {target}")
    if target == root or root not in target.parents:
        parser.error("submission output must be a new directory under this repository")
    target.mkdir(parents=True)
    ignored = shutil.ignore_patterns(*FORBIDDEN_PARTS, ".env", "*.pyc", "*.egg-info")
    roots = ["backend", "frontend", "scripts", "docs"]
    for relative in roots:
        source = root / relative
        shutil.copytree(source, target / relative, ignore=ignored)
    shutil.copytree(root / "data" / "samples", target / "data" / "samples", ignore=ignored)
    for relative in ("README.md", "demo.md", "full_guide.md", "LICENSE", ".dockerignore", ".gitignore", ".env.example", "Dockerfile"):
        source = root / relative
        if source.is_file():
            shutil.copy2(source, target / relative)
    note = """# Submission copy privacy review

Status: local allowlisted review passed on creation. The project owner selected the MIT License; the owner/team should review and explain the submission before delivery.

- Included source, tests, pinned Python/npm locks, documentation, original bounded rule fixtures, and synthetic sample inputs.
- Replaced historical machine-specific absolute paths in the copied text with `<LOCAL_PATH_REDACTED>`; original workspace records remain untouched. Current run commands are documented relative to the repository root.
- Excluded local `.venv`, `node_modules`, build/test output, runtime SQLite databases, saved private source rows, caches, `.git`, `.env`, and non-sample user data.
- Scanned included UTF-8 text for common private Windows/Linux home paths and common private-key/API-token forms; checked for runtime database/log/EVTX types and generated/cache path components.
- `SUBMISSION_MANIFEST.json` records SHA-256 and byte length for each copied source file. It intentionally does not self-hash.
- The root project license is MIT, selected by the project owner. Confirm that contributed material can be distributed and honor the third-party terms recorded in `docs/THIRD_PARTY.md`.
- Wazuh/Hayabusa inputs in `data/samples/external/` are independently authored synthetic schema fixtures; no platform, vendor binary, raw user log, or upstream rule pack is included.
- The historical 4D runtime databases remain in the working repository's ignored `runtime/` tree and are not copied. Readable protocol/report and the release status remain in `docs/`.

The scan is a practical local review, not a guarantee that every sensitive datum or licensing obligation has been found.
"""
    (target / "SUBMISSION_PRIVACY_REVIEW.md").write_text(note, encoding="utf-8")
    redacted_paths = _redact_private_paths(target)
    files, errors = _review(target)
    if errors:
        shutil.rmtree(target)
        raise SystemExit("Privacy review failed:\n- " + "\n- ".join(errors))
    manifest = {path.relative_to(target).as_posix(): {"sha256": _sha256(path), "bytes": path.stat().st_size}
                for path in files}
    (target / "SUBMISSION_MANIFEST.json").write_text(json.dumps({"created_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files), "files": manifest}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "directory": str(target.relative_to(root)),
        "source_files": len(files), "manifest": "SUBMISSION_MANIFEST.json", "privacy_review": "SUBMISSION_PRIVACY_REVIEW.md",
        "private_path_matches": 0, "credential_pattern_matches": 0, "database_or_runtime_log_files": 0,
        "historical_path_replacements": redacted_paths}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
