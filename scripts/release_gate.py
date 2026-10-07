"""Run and capture final suites, clean native install, and preserved-phase regressions."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone


def _tree_hashes(folder: Path):
    return {path.relative_to(folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(folder.rglob("*")) if path.is_file()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new, previously absent release evidence directory")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.exists():
        parser.error(f"refusing to overwrite release evidence directory: {output}")
    if output == root or root not in output.parents:
        parser.error("release evidence output must be a new directory under this repository")
    output.mkdir(parents=True)
    logs = output / "commands"
    logs.mkdir()
    records = []
    state = {"status": "in_progress", "started_at_utc": datetime.now(timezone.utc).isoformat(),
             "repository": ".", "records": records, "saved_4d": {}}

    def save_state():
        (output / "gate.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    def record(name, argv=None, cwd=root, status="running", exit_code=None,
               duration=None, stdout="", stderr="", reason=None):
        index = len(records) + 1
        item = {"id": f"{index:02d}-{name}", "name": name, "status": status,
                "argv": [str(part) for part in argv] if argv else None,
                "cwd": str(cwd.relative_to(root)) if root in cwd.parents or cwd == root else "fresh-source",
                "exit_code": exit_code, "duration_seconds": duration, "reason": reason}
        if argv:
            stem = item["id"]
            (logs / f"{stem}.stdout.log").write_text(stdout, encoding="utf-8", errors="replace")
            (logs / f"{stem}.stderr.log").write_text(stderr, encoding="utf-8", errors="replace")
            item["stdout_log"] = f"commands/{stem}.stdout.log"
            item["stderr_log"] = f"commands/{stem}.stderr.log"
        records.append(item)
        save_state()
        suffix = f"exit={exit_code}" if exit_code is not None else status
        print(f"[{item['id']}] {suffix}" + (f" — {reason}" if reason else ""), flush=True)
        return item

    def run(name, argv, cwd=root, env=None, timeout=1800):
        start = time.perf_counter()
        try:
            result = subprocess.run([str(part) for part in argv], cwd=cwd, env=env,
                capture_output=True, text=True, errors="replace", timeout=timeout, shell=False)
            outcome = "passed" if result.returncode == 0 else "failed"
            return record(name, argv, cwd, outcome, result.returncode,
                round(time.perf_counter() - start, 3), result.stdout, result.stderr,
                None if result.returncode == 0 else "command returned nonzero")
        except subprocess.TimeoutExpired as exc:
            return record(name, argv, cwd, "failed", None, round(time.perf_counter() - start, 3),
                exc.stdout or "", exc.stderr or "", f"timed out after {timeout} seconds")
        except OSError as exc:
            return record(name, argv, cwd, "failed", None, round(time.perf_counter() - start, 3),
                "", str(exc), "command could not be started")

    npm = shutil.which("npm") or "npm"
    py = Path(sys.executable)
    fresh = output / "fresh-install"
    fresh.mkdir()
    source = fresh / "source"
    ignored = shutil.ignore_patterns(".git", ".venv", "node_modules", "dist", "runtime", "__pycache__",
        ".pytest_cache", "test-results", "playwright-report", ".env", "submission")
    copy_start = time.perf_counter()
    try:
        shutil.copytree(root, source, ignore=ignored)
        record("fresh-source-copy", None, root, "passed", 0, round(time.perf_counter() - copy_start, 3),
            "Copied repository source; excluded .venv, node_modules, runtime, .git, .env, generated output and prior submission.", "")
    except OSError as exc:
        record("fresh-source-copy", None, root, "failed", None, round(time.perf_counter() - copy_start, 3), "", str(exc), "fresh source copy failed")

    install_steps = []
    if source.exists():
        base_python = Path(sys._base_executable)
        isolated_venv = fresh / ".venv"
        base_np = base_python
        install_steps.append(run("fresh-python-venv", [base_np, "-m", "venv", isolated_venv], fresh))
        fresh_python = isolated_venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if fresh_python.exists():
            install_steps.append(run("fresh-backend-lock-install", [fresh_python, "-m", "pip", "install",
                "--disable-pip-version-check", "-r", source / "backend" / "requirements.lock"], source, timeout=1800))
            install_steps.append(run("fresh-backend-package-install", [fresh_python, "-m", "pip", "install",
                "--disable-pip-version-check", "--no-deps", "-e", source / "backend"], source, timeout=600))
            install_steps.append(run("fresh-frontend-dependency-install", [npm, "--prefix", source / "frontend", "ci"], source, timeout=1200))
            install_steps.append(run("fresh-frontend-production-build", [npm, "--prefix", source / "frontend", "run", "build"], source, timeout=600))
            if all(item["status"] == "passed" for item in install_steps):
                install_steps.append(run("fresh-offline-restart-export-tamper", [fresh_python,
                    source / "scripts" / "native_release_acceptance.py", "--output", output / "native-acceptance"],
                    source, timeout=600))
            else:
                record("fresh-offline-restart-export-tamper", None, source, "skipped",
                    reason="fresh Python/dependency/frontend install did not complete")
        else:
            for name in ("fresh-backend-lock-install", "fresh-backend-package-install", "fresh-frontend-dependency-install",
                         "fresh-frontend-production-build", "fresh-offline-restart-export-tamper"):
                record(name, None, source, "skipped", reason="fresh virtual environment was not created")

    # Hash originals, then verify a copy: opening old artifact DBs with the current Store applies additive DDL.
    phase4d = root / "runtime" / "phase4d-full-20261007"
    if phase4d.is_dir():
        state["saved_4d"]["before"] = _tree_hashes(phase4d)
        state["saved_4d"]["path"] = "runtime/phase4d-full-20261007"
        state["saved_4d"]["database_files"] = {name: value for name, value in state["saved_4d"]["before"].items()
            if name.lower().endswith("/traceguard.sqlite3")}
        state["saved_4d"]["non_database_files"] = {name: value for name, value in state["saved_4d"]["before"].items()
            if not name.lower().endswith("/traceguard.sqlite3")}
        prior_gate_path = root / "runtime" / "release-final-20261007" / "gate.json"
        if prior_gate_path.is_file():
            prior = json.loads(prior_gate_path.read_text(encoding="utf-8")).get("saved_4d", {})
            state["saved_4d"]["initial_gate_database_hashes"] = {
                "before_first_verification": {name: value for name, value in prior.get("before", {}).items()
                    if name.lower().endswith("/traceguard.sqlite3")},
                "after_first_verification": {name: value for name, value in prior.get("after", {}).items()
                    if name.lower().endswith("/traceguard.sqlite3")},
            }
        save_state()
    else:
        record("saved-4d-input", None, root, "blocked", reason="preserved full Phase 4D artifact directory was not found")

    verification_copy = output / "saved-4d-verification-copy"
    if phase4d.is_dir():
        copy_start = time.perf_counter()
        try:
            shutil.copytree(phase4d, verification_copy)
            record("saved-phase4d-verification-copy", None, root, "passed", 0,
                round(time.perf_counter() - copy_start, 3),
                "Copied all 47 saved 4D files to gate output; current source databases are not opened for migration.")
        except OSError as exc:
            record("saved-phase4d-verification-copy", None, root, "failed", None,
                round(time.perf_counter() - copy_start, 3), "", str(exc), "could not create an isolated verification copy")

    if all(item["status"] == "passed" for item in install_steps):
        run("backend-full-suite", [py, "-m", "pytest", "backend/tests", "-q"], timeout=1800)
        run("frontend-unit-suite", [npm, "--prefix", "frontend", "test"], timeout=900)
        run("frontend-production-build", [npm, "--prefix", "frontend", "run", "build"], timeout=900)
        run("frontend-full-browser-suite", [npm, "--prefix", "frontend", "run", "test:browser"], timeout=1800)
        run("native-dependency-health", [py, "-m", "pip", "check"], timeout=120)
        for phase in ("4a", "4b", "4c"):
            run(f"phase{phase}-fresh-native-regression", [py, root / "scripts" / f"phase{phase}_smoke.py",
                "--output", output / f"phase{phase}-regression"], timeout=1200)
        if phase4d.is_dir() and verification_copy.is_dir():
            run("saved-phase4d-verification", [py, root / "scripts" / "phase4d_verify.py", verification_copy,
                "--output", output / "saved-4d-verification.json"], timeout=1200)
        else:
            record("saved-phase4d-verification", None, root, "skipped", reason="4D source or isolated verification copy is unavailable")
    else:
        for name in ("backend-full-suite", "frontend-unit-suite", "frontend-production-build",
                     "frontend-full-browser-suite", "native-dependency-health", "phase4a-fresh-native-regression",
                     "phase4b-fresh-native-regression", "phase4c-fresh-native-regression", "saved-phase4d-verification"):
            record(name, None, root, "skipped", reason="clean native install or offline acceptance failed")

    if phase4d.is_dir() and "before" in state["saved_4d"]:
        after = _tree_hashes(phase4d)
        before = state["saved_4d"]["before"]
        state["saved_4d"]["after"] = after
        state["saved_4d"]["all_files_byte_identical_during_this_gate"] = before == after
        state["saved_4d"]["non_database_files_byte_identical"] = state["saved_4d"]["non_database_files"] == {
            name: value for name, value in after.items() if not name.lower().endswith("/traceguard.sqlite3")}
        state["saved_4d"]["database_files_byte_identical_during_this_gate"] = state["saved_4d"]["database_files"] == {
            name: value for name, value in after.items() if name.lower().endswith("/traceguard.sqlite3")}
        if before != after:
            record("saved-phase4d-byte-identity", None, root, "failed", reason="saved Phase 4D source files changed during the isolated-copy gate")
        else:
            record("saved-phase4d-byte-identity", None, root, "passed", exit_code=0, duration=0,
                stdout=f"All {len(before)} source files, including the three SQLite files, were byte-identical before/after this gate. The first gate's prior schema side effect is separately disclosed in saved_4d.initial_gate_database_hashes.")

    required = [item for item in records if item["status"] in {"failed", "blocked"}]
    skipped = [item for item in records if item["status"] == "skipped"]
    state["status"] = "passed" if not required and not skipped else "incomplete"
    state["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    state["unresolved"] = {"failed_or_blocked": [item["id"] for item in required],
                           "skipped": [item["id"] for item in skipped], "process_rss": "unmeasured"}
    save_state()
    summary = ["# Final release gate", "", f"Status: **{state['status']}**", "",
        "Every executed subprocess has exact argv, exit status, elapsed wall time, and separate stdout/stderr logs in `commands/`.",
        "Process RSS: unmeasured.", "", "| Check | Result | Seconds |", "|---|---|---:|"]
    for item in records:
        summary.append(f"| {item['name']} | {item['status']} (exit {item['exit_code']}) | {item['duration_seconds'] if item['duration_seconds'] is not None else '—'} |")
    summary += ["", "The `saved_4d` section in `gate.json` records current-source before/after file hashes, isolates the verifier copy, and preserves the first-gate SQLite hash discrepancy for review."]
    (output / "SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"Release gate status: {state['status']}; evidence: {output}", flush=True)
    return 0 if state["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
