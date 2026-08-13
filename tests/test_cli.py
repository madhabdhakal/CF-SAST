"""End-to-end CLI behaviour tests.

These cover the contracts that CI pipelines, the VS Code extension and the
git hooks depend on: exit codes, stream separation, and path formatting.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from harness import run_scanner, scan_json

VULNERABLE = '<cfquery name="q" datasource="ds">\n  SELECT * FROM t WHERE id = #url.id#\n</cfquery>\n'
LOW_ONLY = '<cfset a = hash(pw, "MD5")>\n'


class ProjectCase(unittest.TestCase):
    """Base class providing a disposable project directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, relpath, content):
        target = self.project / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
        return target


class FailOnHigh(ProjectCase):
    """--fail-on-high must gate the build in every output format."""

    def setUp(self):
        super().setUp()
        self.write('vuln.cfm', VULNERABLE)

    def test_console(self):
        code, _, _ = run_scanner(['--files', 'vuln.cfm', '--fail-on-high'], self.project)
        self.assertEqual(code, 1)

    def test_json(self):
        code, _, _ = run_scanner(['--files', 'vuln.cfm', '--fail-on-high', '--json-out'], self.project)
        self.assertEqual(code, 1, 'JSON output must still honour --fail-on-high')

    def test_sarif(self):
        code, _, _ = run_scanner(['--files', 'vuln.cfm', '--fail-on-high', '--sarif'], self.project)
        self.assertEqual(code, 1, 'SARIF output must still honour --fail-on-high')

    def test_scan_all(self):
        code, _, _ = run_scanner(['--scan-all', '--fail-on-high', '--json-out'], self.project)
        self.assertEqual(code, 1)

    def test_no_high_findings_passes(self):
        self.write('vuln.cfm', LOW_ONLY)
        for fmt in ([], ['--json-out'], ['--sarif']):
            with self.subTest(fmt=fmt or 'console'):
                code, _, _ = run_scanner(['--files', 'vuln.cfm', '--fail-on-high'] + fmt, self.project)
                self.assertEqual(code, 0)


class StreamSeparation(ProjectCase):
    """stdout carries only machine-readable payload; status text goes to stderr."""

    def setUp(self):
        super().setUp()
        self.write('vuln.cfm', VULNERABLE)

    def test_scan_all_json_stdout_is_pure_json(self):
        _, out, _ = run_scanner(['--scan-all', '--json-out'], self.project)
        json.loads(out)

    def test_scan_all_sarif_stdout_is_pure_json(self):
        _, out, _ = run_scanner(['--scan-all', '--sarif'], self.project)
        doc = json.loads(out)
        self.assertEqual(doc['version'], '2.1.0')

    def test_batch_progress_goes_to_stderr(self):
        for i in range(60):
            self.write(f'f{i}.cfm', VULNERABLE)
        _, out, err = run_scanner(['--scan-all', '--json-out'], self.project)
        json.loads(out)
        self.assertIn('batch', err.lower())


class PathHandling(ProjectCase):
    """Paths must survive unusual filenames and be reported relative to cwd."""

    def test_filenames_containing_dot_dot_are_scanned(self):
        self.write('report..v2.cfm', VULNERABLE)
        findings = scan_json(['report..v2.cfm'], self.project)
        self.assertTrue(findings, 'a file whose name contains ".." must still be scanned')

    def test_filenames_containing_tilde_are_scanned(self):
        self.write('draft~1.cfm', VULNERABLE)
        findings = scan_json(['draft~1.cfm'], self.project)
        self.assertTrue(findings, 'a file whose name contains "~" must still be scanned')

    def test_reported_paths_are_relative(self):
        self.write('src/vuln.cfm', VULNERABLE)
        findings = scan_json(['src/vuln.cfm'], self.project)
        self.assertTrue(findings)
        for finding in findings:
            self.assertFalse(os.path.isabs(finding['file']),
                             f"expected a repo-relative path, got {finding['file']}")
            self.assertEqual(finding['file'], 'src/vuln.cfm')

    def test_reported_paths_use_forward_slashes(self):
        self.write('src/nested/vuln.cfm', VULNERABLE)
        findings = scan_json(['src/nested/vuln.cfm'], self.project)
        self.assertTrue(findings)
        self.assertNotIn('\\', findings[0]['file'])

    def test_sarif_uri_is_relative(self):
        self.write('src/vuln.cfm', VULNERABLE)
        _, out, _ = run_scanner(['--files', 'src/vuln.cfm', '--sarif'], self.project)
        doc = json.loads(out)
        uri = doc['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertEqual(uri, 'src/vuln.cfm',
                         'GitHub code scanning anchors annotations by repo-relative URI')

    def test_files_outside_project_are_refused(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(outside, ignore_errors=True))
        (outside / 'evil.cfm').write_text(VULNERABLE, encoding='utf-8')
        findings = scan_json([str(outside / 'evil.cfm')], self.project)
        self.assertEqual(findings, [])


class Reporting(ProjectCase):
    def test_console_orders_high_before_medium_before_low(self):
        self.write('a.cfm', VULNERABLE + '<cfoutput>#form.x#</cfoutput>\n' + LOW_ONLY)
        _, out, _ = run_scanner(['--files', 'a.cfm'], self.project)
        order = [line.split(']')[0].lstrip('- [')
                 for line in out.splitlines() if line.startswith('- [')]
        rank = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        self.assertEqual(order, sorted(order, key=lambda s: rank[s]),
                         f'findings listed out of severity order: {order}')

    def test_scanned_count_covers_every_batch(self):
        for i in range(60):
            self.write(f'f{i}.cfm', VULNERABLE)
        _, out, _ = run_scanner(['--scan-all'], self.project)
        self.assertIn('Files scanned: 60', out,
                      'the counter must accumulate across batches, not reset per batch')


class Baseline(ProjectCase):
    def test_baseline_suppresses_known_findings(self):
        self.write('vuln.cfm', VULNERABLE)
        code, _, _ = run_scanner(
            ['--files', 'vuln.cfm', '--baseline', '.sast-baseline.json', '--update-baseline'],
            self.project)
        self.assertEqual(code, 0)
        findings = scan_json(['vuln.cfm'], self.project, ['--baseline', '.sast-baseline.json'])
        self.assertEqual(findings, [])

    def test_baseline_is_portable_across_checkout_paths(self):
        """A baseline recorded in one directory must apply in another.

        This is what makes a locally generated baseline usable in CI, and it
        only holds if finding keys are stored as relative paths.
        """
        self.write('vuln.cfm', VULNERABLE)
        run_scanner(['--files', 'vuln.cfm', '--baseline', '.sast-baseline.json', '--update-baseline'],
                    self.project)
        baseline = (self.project / '.sast-baseline.json').read_text(encoding='utf-8')

        with tempfile.TemporaryDirectory() as other:
            other_path = Path(other)
            (other_path / 'vuln.cfm').write_text(VULNERABLE, encoding='utf-8')
            (other_path / '.sast-baseline.json').write_text(baseline, encoding='utf-8')
            findings = scan_json(['vuln.cfm'], other_path, ['--baseline', '.sast-baseline.json'])
        self.assertEqual(findings, [], 'baseline did not transfer to a different checkout path')

    def test_new_findings_survive_baseline(self):
        self.write('vuln.cfm', VULNERABLE)
        run_scanner(['--files', 'vuln.cfm', '--baseline', '.sast-baseline.json', '--update-baseline'],
                    self.project)
        self.write('other.cfm', VULNERABLE)
        findings = scan_json(['vuln.cfm', 'other.cfm'], self.project,
                             ['--baseline', '.sast-baseline.json'])
        self.assertTrue(findings)
        self.assertEqual({f['file'] for f in findings}, {'other.cfm'})


class Ignore(ProjectCase):
    def test_sastignore_excludes_matching_files(self):
        self.write('.sastignore', 'vendor/*\n')
        self.write('vendor/lib.cfm', VULNERABLE)
        self.write('app.cfm', VULNERABLE)
        findings = scan_json(['vendor/lib.cfm', 'app.cfm'], self.project)
        self.assertEqual({f['file'] for f in findings}, {'app.cfm'})

    def test_init_ignore_creates_file(self):
        code, _, _ = run_scanner(['--init-ignore'], self.project)
        self.assertEqual(code, 0)
        self.assertTrue((self.project / '.sastignore').exists())

    def test_init_ignore_refuses_to_clobber(self):
        self.write('.sastignore', '# mine\n')
        code, _, _ = run_scanner(['--init-ignore'], self.project)
        self.assertEqual(code, 1)
        self.assertEqual((self.project / '.sastignore').read_text(encoding='utf-8'), '# mine\n')


class IncompleteScan(ProjectCase):
    """A scan cut short by a resource limit must not look like a clean pass."""

    def setUp(self):
        super().setUp()
        for i in range(5):
            self.write(f'f{i}.cfm', VULNERABLE)

    def test_timeout_exits_two(self):
        code, _, err = run_scanner(['--scan-all', '--timeout', '0'], self.project)
        self.assertEqual(code, 2, 'a timed-out scan must not exit 0')
        self.assertIn('INCOMPLETE', err)

    def test_timeout_exit_code_survives_json(self):
        code, _, _ = run_scanner(['--scan-all', '--timeout', '0', '--json-out'], self.project)
        self.assertEqual(code, 2)

    def test_findings_gate_still_wins(self):
        """--fail-on-high keeps exit 1 so existing pipelines are unaffected."""
        code, _, _ = run_scanner(['--scan-all', '--fail-on-high'], self.project)
        self.assertEqual(code, 1)

    def test_complete_scan_exits_zero(self):
        code, _, err = run_scanner(['--scan-all'], self.project)
        self.assertEqual(code, 0)
        self.assertNotIn('INCOMPLETE', err)


class SarifDocument(ProjectCase):
    def test_document_shape(self):
        self.write('vuln.cfm', VULNERABLE)
        _, out, _ = run_scanner(['--files', 'vuln.cfm', '--sarif'], self.project)
        doc = json.loads(out)
        self.assertEqual(doc['version'], '2.1.0')
        driver = doc['runs'][0]['tool']['driver']
        self.assertTrue(driver['rules'])
        reported = {r['ruleId'] for r in doc['runs'][0]['results']}
        declared = {r['id'] for r in driver['rules']}
        self.assertTrue(reported <= declared,
                        'every reported ruleId must be declared in tool.driver.rules')


if __name__ == '__main__':
    unittest.main()
