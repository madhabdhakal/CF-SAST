"""Rule regression tests.

One test is generated per fixture in tests/fixtures. A fixture declares its
expectations inline with `EXPECT: <RULE-ID>[, <RULE-ID>...]` comments on the
line where the finding should be reported. Any finding without a matching
marker fails the test, so fixtures double as false-positive guards.

To add coverage, drop a new .cfm file in tests/fixtures and annotate it.
No registration step is required.
"""
import unittest

from harness import FIXTURE_DIR, actual_findings, describe_diff, expected_findings


class RuleFixtures(unittest.TestCase):
    pass


def _make_test(fixture_path):
    def test(self):
        expected = expected_findings(fixture_path)
        actual = actual_findings(fixture_path)
        if expected != actual:
            self.fail(f'{fixture_path.name}:\n  {describe_diff(expected, actual)}')
    test.__doc__ = f'fixture {fixture_path.name}'
    return test


def _register():
    fixtures = sorted(FIXTURE_DIR.glob('*.cfm'))
    if not fixtures:
        raise RuntimeError(f'no fixtures found in {FIXTURE_DIR}')
    for fixture in fixtures:
        setattr(RuleFixtures, f'test_{fixture.stem}', _make_test(fixture))


_register()


if __name__ == '__main__':
    unittest.main()
