"""Shared helpers for the CFML SAST test suite.

Fixtures are executed in a throwaway directory rather than in the repository
so that the repo's own .sastignore cannot influence results, and so that
relative-path assertions have a stable root.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER = REPO_ROOT / 'scripts' / 'cfml_sast_simple.py'
FIXTURE_DIR = Path(__file__).resolve().parent / 'fixtures'

# "EXPECT: CF-XSS-001, CF-LDAP-001" in either a CFML or a CFScript comment.
EXPECT_MARKER = re.compile(r'EXPECT:\s*([A-Z0-9\-,\s]+?)\s*(?:--->|$)', re.MULTILINE)
RULE_ID = re.compile(r'CF-[A-Z]+-\d+')


def run_scanner(args, cwd):
    """Invoke the scanner and return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(SCANNER)] + list(args),
        cwd=str(cwd), capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def scan_json(files, cwd, extra_args=()):
    """Run a --json-out scan and return the parsed findings list.

    Parsing stdout strictly as JSON is deliberate: it makes any progress or
    status text leaking onto stdout a test failure rather than a silent
    downstream parsing problem.
    """
    args = ['--files'] + list(files) + ['--json-out'] + list(extra_args)
    code, out, err = run_scanner(args, cwd)
    try:
        findings = json.loads(out)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f'stdout was not valid JSON ({exc}).\n--- stdout ---\n{out}\n--- stderr ---\n{err}'
        )
    return findings


def expected_findings(fixture_path):
    """Parse inline EXPECT: markers into a set of (line, rule_id) pairs."""
    expected = set()
    for lineno, line in enumerate(fixture_path.read_text(encoding='utf-8').splitlines(), start=1):
        for marker in EXPECT_MARKER.findall(line):
            for rule_id in RULE_ID.findall(marker):
                expected.add((lineno, rule_id))
    return expected


def actual_findings(fixture_path):
    """Scan a fixture in isolation and return a set of (line, rule_id) pairs."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / fixture_path.name
        shutil.copy2(fixture_path, target)
        findings = scan_json([fixture_path.name], tmp)
    return {(f['line'], f['rule_id']) for f in findings}


def describe_diff(expected, actual):
    """Render a readable report of missed and spurious findings."""
    missed = sorted(expected - actual)
    spurious = sorted(actual - expected)
    parts = []
    if missed:
        parts.append('missed (expected but not reported):\n' +
                     '\n'.join(f'    line {ln}: {rid}' for ln, rid in missed))
    if spurious:
        parts.append('spurious (reported but not expected):\n' +
                     '\n'.join(f'    line {ln}: {rid}' for ln, rid in spurious))
    return '\n  '.join(parts)
