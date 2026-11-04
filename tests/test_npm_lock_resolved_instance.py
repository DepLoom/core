import unittest

from resolution_inventory import npm_lock_resolved_instance, npm_lock_resolved_version


class NpmLockResolvedInstanceTests(unittest.TestCase):
    def test_same_package_resolves_to_distinct_owner_instances(self):
        packages = {
            "node_modules/react": {"version": "19.0.0"},
            "packages/legacy/node_modules/react": {"version": "18.3.1"},
        }
        self.assertEqual(npm_lock_resolved_instance(packages, "react", "packages/app"),
                         ("node_modules/react", "19.0.0"))
        self.assertEqual(npm_lock_resolved_instance(packages, "react", "packages/legacy"),
                         ("packages/legacy/node_modules/react", "18.3.1"))
        self.assertEqual(npm_lock_resolved_version(packages, None, "react", "packages/legacy"),
                         "18.3.1")

    def test_workspace_link_keeps_key_and_does_not_fall_back_if_target_is_missing(self):
        packages = {
            "packages/app/node_modules/ui": {"link": True, "resolved": "packages/ui"},
            "packages/ui": {"version": "1.0.0"},
            "node_modules/ui": {"version": "2.0.0"},
        }
        self.assertEqual(npm_lock_resolved_instance(packages, "ui", "packages/app"),
                         ("packages/app/node_modules/ui", "1.0.0"))
        del packages["packages/ui"]
        self.assertIsNone(npm_lock_resolved_instance(packages, "ui", "packages/app"))
