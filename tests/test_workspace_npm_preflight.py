import unittest

import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
from workspace_npm_preflight import check_workspace_lock, run_workspace_npm_preflight


class WorkspaceLockChecks(unittest.TestCase):
    def test_same_direct_versions_do_not_hide_incompatible_hoisted_peer(self):
        assignment = {
            (".", "dependencies", "react"): "19.0.0",
            ("packages/legacy", "dependencies", "react"): "18.3.1",
            ("packages/legacy", "dependencies", "react-dom"): "18.3.1",
        }
        renderer = {"version": "18.3.1", "peerDependencies": {"react": ">= 18.3.1 < 19"}}
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

    def test_existing_root_overrides_reach_npm_unchanged(self):
        overrides = {"parent@^1": {".": "1.2.0", "@scope/child": "$@scope/child"}}
        root = {"workspaces": ["packages/*"], "dependencies": {"@scope/child": "1.0.0"},
                "overrides": overrides}
        member = {"name": "app", "version": "1.0.0"}
        baseline = {"lockfileVersion": 3, "packages": {
            "": {"workspaces": root["workspaces"], "dependencies": root["dependencies"]},
            "packages/app": member,
            "node_modules/@scope/child": {"version": "1.0.0"},
        }}
        inputs = {owner: json.dumps(project).encode() for owner, project in ((".", root), ("packages/app", member))}
        assignment = {(".", "dependencies", "@scope/child"): "1.0.0"}

        def resolve(argv, workspace, **kwargs):
            self.assertEqual(json.loads((workspace / "package.json").read_bytes())["overrides"], overrides)
            if argv[1] == "-e":
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "status": "RESOLUTION_PASSED", "code": "LOCK_ASSIGNMENT_AND_PEERS_MATCH", "nodeCount": 3,
                }))
            self.assertEqual(argv[argv.index("--registry") + 1], "https://mirror.example.invalid/npm")
            self.assertIn("--strict-peer-deps=true", argv)
            return subprocess.CompletedProcess(argv, 0, "")

        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight._npm_command", return_value=[__file__, __file__]),
              patch("workspace_npm_preflight.run_supervised", side_effect=resolve) as runner):
            options = {"artifacts": Path(temp), "cache": Path(temp), "registry": "https://mirror.example.invalid/npm"}
            result = run_workspace_npm_preflight(inputs, json.dumps(baseline).encode(), assignment, frozenset(), **options)
            self.assertEqual(result["status"], "RESOLUTION_PASSED")
            self.assertEqual(result["runtime"], "NOT_RUN")
            for invalid in ({"parent": {"child": "$not-in-root"}},
                            {"parent": {"child": "https://example.invalid/archive.tgz"}},
                            {"parent@file:./x": "1.2.0"}):
                inputs["."] = json.dumps({**root, "overrides": invalid}).encode()
                result = run_workspace_npm_preflight(
                    inputs, json.dumps(baseline).encode(), assignment, frozenset(), **options)
                self.assertEqual(result["code"], "INVALID_WORKSPACE_PREFLIGHT_INPUT")
            self.assertEqual(runner.call_count, 2)

    def test_native_timeout_is_unknown_and_never_learned(self):
        projects = {
            ".": {"workspaces": ["packages/*"], "dependencies": {"react": "18.3.1"}},
            "packages/app": {"name": "app", "version": "1.0.0"},
        }
        lock = {"lockfileVersion": 3, "packages": {
            "": projects["."], "packages/app": projects["packages/app"],
            "node_modules/react": {"version": "18.3.1"},
        }}
        inputs = {owner: json.dumps(manifest).encode() for owner, manifest in projects.items()}
        target = (".", "dependencies", "react")
        with (tempfile.TemporaryDirectory() as temp,
              patch("workspace_npm_preflight._npm_command", return_value=[__file__, __file__]),
              patch("workspace_npm_preflight.run_supervised", side_effect=subprocess.TimeoutExpired(["npm"], 1))):
            result = run_workspace_npm_preflight(
                inputs, json.dumps(lock).encode(), {target: "19.0.0"}, frozenset({target}),
                artifacts=Path(temp) / "artifacts", cache=Path(temp) / "cache",
                registry="https://registry.npmjs.org/", timeout_seconds=1,
            )
        self.assertEqual((result["status"], result["code"]), ("UNKNOWN", "RESOLVER_TIMEOUT"))
        self.assertFalse(result["learningAllowed"])
        self.assertEqual(result["installation"], "NOT_RUN")
