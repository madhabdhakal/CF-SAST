"""Integration tests for the pre-push hook.

The hook is the least-exercised part of the project and the easiest to break:
it depends on the installed directory layout, on the shell, and on git. These
tests install it into a throwaway repository and actually run it.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness import REPO_ROOT, SCANNER

PREPUSH = REPO_ROOT / 'scripts' / 'sast' / 'prepush.sh'
VULNERABLE = '<cfquery name="q" datasource="ds">\n  SELECT * FROM t WHERE id = #url.id#\n</cfquery>\n'
SAFE = '<cfoutput>hello</cfoutput>\n'

HAVE_BASH = shutil.which('bash') is not None
HAVE_GIT = shutil.which('git') is not None


@unittest.skipUnless(HAVE_BASH and HAVE_GIT, 'requires bash and git')
class PrePushHook(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.com')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'commit.gpgsign', 'false')
        (self.repo / 'README.md').write_text('seed\n', encoding='utf-8')
        self.git('add', '-A')
        self.git('commit', '-qm', 'initial')

    def git(self, *args):
        return subprocess.run(['git'] + list(args), cwd=str(self.repo),
                              capture_output=True, text=True, check=True)

    def install(self, layout='CFSAST'):
        target = self.repo / layout
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SCANNER, target / 'cfml_sast_simple.py')
        hook = target / 'prepush.sh'
        shutil.copy2(PREPUSH, hook)
        hook.chmod(0o755)
        return hook

    def commit_file(self, name, content):
        (self.repo / name).write_text(content, encoding='utf-8')
        self.git('add', '-A')
        self.git('commit', '-qm', f'add {name}')

    def run_hook(self, hook):
        return subprocess.run(['bash', str(hook)], cwd=str(self.repo),
                              capture_output=True, text=True)

    def test_blocks_push_on_high_severity(self):
        hook = self.install()
        self.commit_file('vuln.cfm', VULNERABLE)
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 1,
                         f'hook should block the push\nstdout={proc.stdout}\nstderr={proc.stderr}')
        self.assertIn('CF-SQLI-001', proc.stdout)

    def test_allows_push_when_clean(self):
        hook = self.install()
        self.commit_file('safe.cfm', SAFE)
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 0,
                         f'stdout={proc.stdout}\nstderr={proc.stderr}')

    def test_no_cfml_changes_is_a_pass(self):
        hook = self.install()
        self.commit_file('notes.txt', 'nothing to see\n')
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 0)
        self.assertIn('no changed CFML files', proc.stdout)

    def test_finds_scanner_in_source_checkout_layout(self):
        """A source checkout keeps the scanner in scripts/, not CFSAST/."""
        hook = self.install(layout='scripts')
        self.commit_file('vuln.cfm', VULNERABLE)
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 1,
                         f'stdout={proc.stdout}\nstderr={proc.stderr}')

    def test_reports_missing_scanner_clearly(self):
        target = self.repo / 'CFSAST'
        target.mkdir()
        hook = target / 'prepush.sh'
        shutil.copy2(PREPUSH, hook)
        hook.chmod(0o755)
        self.commit_file('vuln.cfm', VULNERABLE)
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 1)
        self.assertIn('scanner not found', proc.stderr)

    def test_handles_filenames_with_spaces(self):
        hook = self.install()
        self.commit_file('my report.cfm', VULNERABLE)
        proc = self.run_hook(hook)
        self.assertEqual(proc.returncode, 1,
                         f'stdout={proc.stdout}\nstderr={proc.stderr}')

    def test_root_commit_without_upstream(self):
        """A repo whose only commit is the root must not crash on HEAD~1."""
        fresh = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fresh, True)
        subprocess.run(['git', 'init', '-q'], cwd=str(fresh), check=True)
        for k, v in (('user.email', 't@e.com'), ('user.name', 'T'), ('commit.gpgsign', 'false')):
            subprocess.run(['git', 'config', k, v], cwd=str(fresh), check=True)
        (fresh / 'CFSAST').mkdir()
        shutil.copy2(SCANNER, fresh / 'CFSAST' / 'cfml_sast_simple.py')
        hook = fresh / 'CFSAST' / 'prepush.sh'
        shutil.copy2(PREPUSH, hook)
        hook.chmod(0o755)
        (fresh / 'vuln.cfm').write_text(VULNERABLE, encoding='utf-8')
        subprocess.run(['git', 'add', '-A'], cwd=str(fresh), check=True)
        subprocess.run(['git', 'commit', '-qm', 'root'], cwd=str(fresh), check=True)

        proc = subprocess.run(['bash', str(hook)], cwd=str(fresh),
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1,
                         f'stdout={proc.stdout}\nstderr={proc.stderr}')


if __name__ == '__main__':
    unittest.main()
