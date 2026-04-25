#!/usr/bin/env python3
"""Validate hunts/backlog/*.yaml against the TaHiTI hypothesis schema.

Usage:
    python3 scripts/validate_hypothesis.py                   # validate all
    python3 scripts/validate_hypothesis.py path/to/file.yaml # validate one

Exit code 0 = all valid; 1 = any failed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

# Allow running from repo root or scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.hypothesis_schema import Hypothesis  # noqa: E402


def validate_file(path: Path) -> tuple[bool, str]:
    try:
        text = path.read_text()
    except (FileNotFoundError, OSError) as e:
        return False, f"could not read file: {e}"
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {e}"
    if not isinstance(data, dict):
        return False, f"top-level YAML must be a mapping (got {type(data).__name__})"
    try:
        Hypothesis(**data)
    except ValidationError as e:
        return False, str(e)
    return True, "ok"


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        targets = [Path(p) for p in argv[1:]]
    else:
        backlog = Path(__file__).resolve().parent.parent / "hunts" / "backlog"
        targets = sorted(backlog.glob("H-*.yaml"))

    failures = 0
    for path in targets:
        ok, msg = validate_file(path)
        marker = "PASS" if ok else "FAIL"
        print(f"[{marker}] {path}: {msg if not ok else ''}".rstrip())
        if not ok:
            failures += 1

    if failures:
        print(f"\n{failures} hypothesis file(s) failed validation.", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
