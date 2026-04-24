#!/usr/bin/env python3
"""Scan files for sensitive identifiers that should not appear in this repo.

Usage:
    check_sensitive.py                      # scans entire working tree
    check_sensitive.py path1 path2 ...      # scans specific paths
    check_sensitive.py --staged             # scans staged files only (pre-commit)

Exits 0 if clean, 1 if any match found.

Rules are intentionally specific: we allow generic placeholders in docs/tests
(e.g. 'kids-laptop', '10.0.0.5') but block real identifiers from the home
network (device names, home-net /24, Windows/Linux usernames, emails).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# (label, regex). Patterns are compiled once at import.
RULES: list[tuple[str, re.Pattern[str]]] = [
    ("home-lan-24",          re.compile(r"\b192\.168\.168\.\d+\b")),
    ("device-name:theblacksilence", re.compile(r"\btheblacksilence\b", re.I)),
    ("device-name:The-Pinky",       re.compile(r"\bThe-Pinky\b")),
    ("device-name:Ne7csg",          re.compile(r"\bNe7csg\b")),
    ("device-name:StunningBanana",  re.compile(r"\bStunningBanana\b")),
    ("first-name:Yassir",           re.compile(r"\bYassir\b")),
    ("windows-user-path",    re.compile(r"C:\\Users\\yasir\\", re.I)),
    ("linux-home-path",      re.compile(r"/home/yasir/")),
    ("user-ref",             re.compile(r'"user"\s*:\s*"yasir"')),
    ("email",                re.compile(r"yasirhamza@\w+\.\w+")),
    ("investigation-domain:rapidshare", re.compile(r"\b(klk|p36)\.rapidshare\.cc\b", re.I)),
    ("investigation-domain:4pjoxehw",   re.compile(r"\b4pjoxehw\.com\b", re.I)),
]

# Paths never scanned (binary / vendored / generated).
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz"}

# The scanner itself must mention the identifiers it blocks — exempt it.
SELF_EXEMPT = {
    "scripts/check_sensitive.py",
    "mcp-server/tests/test_check_sensitive.py",
}


def _iter_tree() -> list[Path]:
    out: list[Path] = []
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO_ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        out.append(rel)
    return out


def _staged_files() -> list[Path]:
    res = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return [Path(line) for line in res.stdout.splitlines() if line.strip()]


def scan(paths: list[Path]) -> list[tuple[Path, int, str, str]]:
    """Return list of (path, lineno, rule_label, matched_snippet)."""
    findings: list[tuple[Path, int, str, str]] = []
    for rel in paths:
        if str(rel) in SELF_EXEMPT:
            continue
        abs_p = REPO_ROOT / rel
        if not abs_p.is_file():
            continue
        try:
            text = abs_p.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, pat in RULES:
                m = pat.search(line)
                if m:
                    snippet = line.strip()
                    if len(snippet) > 160:
                        snippet = snippet[:157] + "..."
                    findings.append((rel, lineno, label, snippet))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="files to scan (default: full tree)")
    ap.add_argument("--staged", action="store_true", help="scan git staged files only")
    args = ap.parse_args()

    if args.staged:
        paths = _staged_files()
    elif args.paths:
        paths = [Path(p).resolve().relative_to(REPO_ROOT) for p in args.paths]
    else:
        paths = _iter_tree()

    findings = scan(paths)
    if not findings:
        return 0

    print(f"FAIL: {len(findings)} sensitive-string match(es)", file=sys.stderr)
    for rel, lineno, label, snippet in findings:
        print(f"  {rel}:{lineno} [{label}]  {snippet}", file=sys.stderr)
    print("", file=sys.stderr)
    print("To override (only if confirmed safe): git commit --no-verify", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
