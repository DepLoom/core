import json
from pathlib import Path
import tempfile
import unittest

from manual_dependency_audit import yarn_classic_finding_roots


class YarnClassicFindingRootsTests(unittest.TestCase):
    def trace(self, manifest, lock, affected, **options):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
            (project / "yarn.lock").write_text("# yarn lockfile v1\n\n" + lock, encoding="utf-8")
            return yarn_classic_finding_roots(project, affected, **options)

    def test_reports_distinct_declarations_and_exact_versions_with_bounded_witnesses(self):
        lock = """runtime@^1:
  version "1.0.0"
  dependencies:
    child "^1"

tool@^1:
  version "1.0.0"
  optionalDependencies:
    child "^2"

another-tool@^1:
  version "1.0.0"
  dependencies:
    child "^2"

child@^1:
  version "1.0.0"

child@^2:
  version "2.0.0"
"""
        manifest = {
            "dependencies": {"runtime": "^1"},
            "devDependencies": {"tool": "^1", "another-tool": "^1"},
        }
        result = self.trace(manifest, lock, {("child", "2.0.0")}, max_paths=1)
        self.assertTrue(result["complete"])
        finding = result["findings"]["child", "2.0.0"]
        self.assertEqual(finding["rootCount"], 2)
        self.assertEqual(len(finding["paths"]), 1)
        witness = finding["paths"][0]
        self.assertEqual(witness["section"], "devDependencies")
        self.assertEqual(witness["directPackage"], "another-tool")
        self.assertEqual(witness["chain"][-1], {"name": "child", "version": "2.0.0"})

    def test_missing_selector_does_not_borrow_a_same_name_lock_entry(self):
        lock = """tool@^1:
  version "1.0.0"
  dependencies:
    child "^2"

child@^1:
  version "1.0.0"
"""
        result = self.trace({"devDependencies": {"tool": "^1"}}, lock, {("child", "1.0.0")})
        self.assertFalse(result["complete"])
        self.assertEqual(result["findings"]["child", "1.0.0"], {"rootCount": 0, "paths": []})
