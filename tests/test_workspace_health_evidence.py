"""Tests for the Core-owned registry evidence path and privacy boundary."""
import unittest
from unittest.mock import Mock, call

from dependency_live_roadmap_generator import DeadlineClock, LiveDataClient, VulnerabilityEvidenceUnavailable
from workspace_health_evidence import collect_workspace_health_facts
from workspace_health_policy import WorkspaceHealthPolicy
from workspace_peer_model import declaration_id, plan_workspace_from_registry


REGISTRY = "https://registry.example.invalid"
APP = ("packages/app", "dependencies", "demo")
LEGACY = ("packages/legacy", "dependencies", "demo")
HELD = (".", "dependencies", "held")


def packument(name):
    return {"name": name, "dist-tags": {"latest": "2.0.0"},
            "time": {"1.0.0": "2025-01-01T00:00:00Z", "2.0.0": "2026-05-01T00:00:00Z"},
            "versions": {v: {"name": name, "version": v,
                             "dist": {"tarball": f"{REGISTRY}/{name}/-/{name}-{v}.tgz"}}
                         for v in ("1.0.0", "2.0.0")}}


class WorkspaceRegistryHealthTests(unittest.TestCase):
    def setUp(self):
        self.client = LiveDataClient(REGISTRY, timeout=1, batch_size=10, sleep_sec=0)
        self.client.draft = True
        self.client.set_deadline(DeadlineClock(20))
        self.client.fetch_npm_metadata = Mock(side_effect=packument)
        self.client.query_osv_versions = Mock(side_effect=lambda _, versions: {v: [] for v in versions})
        self.packages = {
            "packages/app/node_modules/demo": {"version": "1.0.0"},
            "packages/legacy/node_modules/demo": {"version": "2.0.0"},
            "node_modules/held": {"version": "2.0.0"},
        }
        self.declarations = {APP: "1.0.0", LEGACY: "2.0.0", HELD: "2.0.0"}

    def plan(self, allowed=frozenset({"demo", "held"})):
        return plan_workspace_from_registry(
            self.packages, self.declarations, {APP: (1, 2)}, {}, self.client,
            candidate_versions={APP: ("1.0.0", "2.0.0")},
            health_policy=WorkspaceHealthPolicy("yellow", 80), osv_allowed_names=allowed,
        )

    def test_registry_path_deduplicates_exact_osv_and_keeps_held_declarations(self):
        result = self.plan()
        self.assertEqual(result["assignment"][declaration_id(APP)], "2.0.0")
        self.assertEqual(result["assignment"][declaration_id(LEGACY)], "2.0.0")
        self.assertEqual(result["policy"]["lagDenominator"], 3)
        self.assertEqual(result["policy"]["evidence"]["exactVersionCount"], 3)
        self.assertEqual(result["policy"]["evidence"]["unknownSecurityVersionCount"], 0)
        self.assertCountEqual(self.client.fetch_npm_metadata.call_args_list, [call("demo"), call("held")])
        self.assertEqual(self.client.query_osv_versions.call_args_list,
                         [call("demo", ["1.0.0", "2.0.0"]), call("held", ["2.0.0"])])

    def test_unapproved_osv_name_remains_unknown_and_is_not_sent(self):
        result = self.plan(frozenset({"demo"}))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])
        self.assertEqual(result["policy"]["evidence"]["osvSkippedNameCount"], 1)
        self.assertEqual(result["policy"]["evidence"]["unknownSecurityVersionCount"], 1)
        self.client.query_osv_versions.assert_called_once_with("demo", ["1.0.0", "2.0.0"])

    def test_osv_outage_and_missing_date_are_not_clean_or_stale(self):
        meta = packument("demo")
        del meta["time"]["1.0.0"]
        self.client.query_osv_versions.side_effect = VulnerabilityEvidenceUnavailable("unavailable")
        facts, evidence = collect_workspace_health_facts(
            self.client, {"demo": meta}, {"demo": ("1.0.0", "2.0.0")},
            lag_months=12, osv_allowed_names=frozenset({"demo"}),
        )
        self.assertIsNone(facts["demo", "1.0.0"].lag_ok)
        self.assertTrue(facts["demo", "2.0.0"].lag_ok)
        self.assertIsNone(facts["demo", "2.0.0"].severities)
        self.assertEqual((evidence["unknownLagVersionCount"], evidence["unknownSecurityVersionCount"]), (1, 2))

    def test_no_policy_network_without_a_deadline(self):
        self.client.set_deadline(None)
        with self.assertRaisesRegex(ValueError, "WORKSPACE_POLICY_REGISTRY_DEADLINE_REQUIRED"):
            self.plan()
        self.client.fetch_npm_metadata.assert_not_called()
