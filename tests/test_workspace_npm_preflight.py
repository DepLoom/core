import unittest

import json
from pathlib import Path
from unittest.mock import patch
from workspace_npm_preflight import check_workspace_lock, run_workspace_npm_preflight


class WorkspaceLockChecks(unittest.TestCase):
    def test_same_direct_versions_do_not_hide_incompatible_hoisted_peer(self):
        assignment = {
            (".", "dependencies", "react"): "19.0.0",
            ("packages/legacy", "dependencies", "react"): "18.3.1",
            ("packages/legacy", "dependencies", "react-dom"): "18.3.1",
        }
        renderer = {"version": "18.3.1", "peerDependencies": {"react": "^18.3.1"}}
        packages = {
            "node_modules/react": {"version": "19.0.0"},
            "packages/legacy/node_modules/react": {"version": "18.3.1"},
            "packages/legacy/node_modules/react-dom": renderer,
        }
        accepted = check_workspace_lock(packages, assignment)
        self.assertEqual(accepted["status"], "RESOLUTION_PASSED")
        self.assertEqual(accepted["installation"], "NOT_RUN")

        packages["node_modules/react-dom"] = packages.pop("packages/legacy/node_modules/react-dom")
        rejected = check_workspace_lock(packages, assignment)
        self.assertEqual(rejected["code"], "LOCK_PEER_MISMATCH")
        self.assertEqual(rejected["providerVersion"], "19.0.0")
        self.assertFalse(rejected["learningAllowed"])

    def test_absent_optional_peer_allowed_but_incompatible_present_peer_rejected(self):
        packages = {"node_modules/consumer": {
            "version": "1.0.0", "peerDependencies": {"react": "^18"},
            "peerDependenciesMeta": {"react": {"optional": True}},
        }}
        self.assertEqual(check_workspace_lock(packages, {})["status"], "RESOLUTION_PASSED")
        packages["node_modules/react"] = {"version": "19.0.0"}
        self.assertEqual(check_workspace_lock(packages, {})["code"], "LOCK_PEER_MISMATCH")


    def test_protected_assignment_change_is_rejected_before_npm(self):
        projects = {
            ".": {"workspaces": ["packages/*"]},
            "packages/legacy": {"dependencies": {"react": "18.3.1"}},
        }
        lock = {"lockfileVersion": 3, "packages": {
            "": projects["."],
            "packages/legacy": projects["packages/legacy"],
            "node_modules/react": {"version": "18.3.1"},
        }}
        inputs = {owner: json.dumps(manifest).encode() for owner, manifest in projects.items()}
        with patch("workspace_npm_preflight.run_supervised") as runner:
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), {("packages/legacy", "dependencies", "react"): "19.0.0"},
                frozenset(), artifacts=Path("unused"), cache=Path("unused"), registry="https://registry.npmjs.org/",
            )
        runner.assert_not_called()
        self.assertEqual(result["code"], "UNAUTHORIZED_DECLARATION_DELTA")
