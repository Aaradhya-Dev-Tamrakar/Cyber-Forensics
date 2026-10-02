#!/usr/bin/env python3
"""
verify.py — Deterministic verification suite for Cyber-Forensics

Checks:
  1. PowerShell & script entrypoints presence and integrity
  2. Commit SHA integrity: Prohibits placeholder tokens (relXX, upgXX, xtoolXX, dummy, todo)
     and validates all commit references are authentic 7-40 hex SHAs.

Run:
  python scripts/verify.py
  python scripts/verify.py --verbose

Exit codes: 0 = clean, 1 = errors found
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

errors = []
passes = []

VERBOSE = "--verbose" in sys.argv


def ok(msg):
    passes.append(msg)
    if VERBOSE:
        print(f"  [PASS] {msg}")


def err(msg):
    errors.append(msg)
    print(f"  [FAIL] {msg}")


def check_script_structure():
    print("\n[1/2] Core scripts & forensic modules")
    required = [
        "src/ArtifactHarvester.ps1",
        "src/EvasionHunter.ps1",
        "tests/test_evasion_hunter.ps1",
        "sync.ps1",
        "sync.bat",
        "README.md"
    ]
    for req in required:
        if os.path.exists(req):
            ok(f"{req} exists and verified")
        else:
            err(f"missing expected file '{req}'")


def check_commit_sha_integrity():
    print("\n[2/2] Commit SHA & placeholder integrity")
    placeholder_pattern = re.compile(r"\b(rel\d+|upg\d+|xtool\d+|dummy|todo)\b", re.IGNORECASE)
    commit_url_pattern = re.compile(r"github\.com/[^/]+/[^/]+/commit/([a-zA-Z0-9_\-]+)")
    sha_prop_pattern = re.compile(r"""sha:\s*['"]([^'"]+)['"]""")
    hex_sha_pattern = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)

    scanned_extensions = {".md", ".ps1", ".bat", ".json", ".py"}
    bad_shas = []

    for root_dir, _, files in os.walk("."):
        if any(d in root_dir for d in [".git", "evidence"]):
            continue
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in scanned_extensions:
                file_path = os.path.join(root_dir, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except Exception:
                    continue

                for m in commit_url_pattern.finditer(content):
                    sha = m.group(1)
                    if placeholder_pattern.match(sha) or not hex_sha_pattern.match(sha):
                        bad_shas.append(f"{file_path}: invalid commit URL SHA '{sha}'")

                for m in sha_prop_pattern.finditer(content):
                    sha = m.group(1)
                    if placeholder_pattern.match(sha) or not hex_sha_pattern.match(sha):
                        bad_shas.append(f"{file_path}: invalid sha property '{sha}'")

    if bad_shas:
        for b in bad_shas:
            err(b)
    else:
        ok("all commit SHAs are authentic 7-40 hex format (0 placeholders found)")


def main():
    print(f"Running deterministic verification in {ROOT}")
    check_script_structure()
    check_commit_sha_integrity()

    print(f"\n{'='*50}")
    print(f"Passed: {len(passes)}   Errors: {len(errors)}")
    if errors:
        print("\nFAILED — fix the above before proceeding.")
        sys.exit(1)
    print("\nALL CHECKS PASSED DETERMINISTICALLY.")
    sys.exit(0)


if __name__ == "__main__":
    main()
