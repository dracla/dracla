"""Core discovery keeps the corpus completeness assertion last."""

from pathlib import Path
import unittest


def load_tests(loader, tests, pattern):
    # unittest's loading-packages guard prevents recursion during this discover.
    root = Path(__file__).resolve().parents[2]
    suite = loader.discover(str(root / "core/tests"), pattern=pattern or "test*.py", top_level_dir=str(root))
    from core.tests.corpus_consumption import CLAIMS
    suite.addTest(unittest.FunctionTestCase(CLAIMS.assert_complete, description="complete Python corpus consumption"))
    return suite
