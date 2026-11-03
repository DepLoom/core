"""Focused generic exact-version planning tests; no network, no model calls."""
from __future__ import annotations
import json
import os
import unittest
from unittest.mock import patch, MagicMock

import dependency_live_roadmap_generator as roadmap
from draft_decision_contract import (
    EXPLICIT_VERSIONS, normalize_decision_contract, version_line_allowed,
)
from peer_solver_z3 import solve_z3_exact


class ExactVersionObjectiveTests(unittest.TestCase):
    REGISTRY = "https://registry.example.invalid"

    def setUp(self):
        self.intent = {
            "objective": EXPLICIT_VERSIONS,
            "targetMode": "pinned",
            "mutablePackages": ["sample-lib"],
            "approvedVersionLines": {"sample-lib": [2]},
            "exactTargets": {"sample-lib": "2.3.0"},
        }
        self.env = patch.dict(os.environ, {
            "DEPLOOM_BASELINE_INTENT_JSON": json.dumps(self.intent)
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        roadmap._BASELINE_INTENT_CACHE_RAW = "<unset>"
        self.client = roadmap.LiveDataClient(
            self.REGISTRY, timeout=1, batch_size=10, sleep_sec=0,
        )
        self.client.draft = True
        self.network = patch.object(self.client.session, "request",
                                    side_effect=AssertionError("no network allowed"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.types = patch.object(
            self.client, "registry_version_type_declarations_ok", return_value=False)
        self.types.start()
        self.addCleanup(self.types.stop)
        self.runtime = patch.object(
            self.client, "registry_version_runtime_entrypoint_ok", return_value=False)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        # A missing exact version returns an independently evidenced 404,
        # never a fabricated tarball. Positive recovery is tested below.
        self.exact_lookup = patch.object(
            self.client, "registry_exact_version_manifest",
            return_value=(None, "EXACT_VERSION_NOT_PUBLISHED"))
        self.exact_lookup.start()
        self.addCleanup(self.exact_lookup.stop)

    def row(self,name="sample-lib",current="1.0.0",spec="1.0.0"):
        return roadmap.DependencyRow(
            project="synthetic",package_dir=".",name=name,kind="runtime",
            requested_spec=spec,current_version=current,
            current_source="lockfile",latest_version="2.3.0",current_vulns="0",
            min_no_critical=current,min_no_high=current,min_no_vuln=current,
            min_lag_12m=current,min_lag_9m=current,min_lag_6m=current,
            min_lag_3m=current,group=1,reason="synthetic objective test",
            notes="",target_default=roadmap.NO_ACTION,
            target_yellow=roadmap.NO_ACTION,target_green=roadmap.NO_ACTION,
            draft_scan_state="done",
            vuln_evidence_by_version={current:"0", "2.3.0":"0"},
        )

    def add_metadata(self,name,versions,*,peer_on_target=None):
        data={}
        for v in versions:
            md={"dist":{"tarball":f"{self.REGISTRY}/{name}/-/{name}-{v}.tgz"}}
            if v=="2.3.0" and peer_on_target:
                md["peerDependencies"]=dict(peer_on_target)
            data[v]=md
        self.client.npm_cache[name]={"versions":data}

    def test_contract_v1_untouched_v2_exact_semver_and_scope(self):
        self.assertEqual({
            "version":1,"targetMode":"pinned","objective":"minimum-change-to-policy",
            "mutablePackages":None,"approvedVersionLines":{},
        },normalize_decision_contract())
        c=normalize_decision_contract(self.intent)
        self.assertEqual(2,c["version"])
        self.assertEqual({"sample-lib":"2.3.0"},c["exactTargets"])
        self.assertTrue(version_line_allowed("sample-lib","1.0.0","2.3.0",c))
        self.assertFalse(version_line_allowed("sample-lib","1.0.0","2.4.0",c))
        self.assertFalse(version_line_allowed("sample-other","1.0.0","2.3.0",c))
        for modified in (
            {"exactTargets":{"sample-other":"2.3.0"}},
            {"exactTargets":{"sample-lib":"^2.3.0"}},
            {"exactTargets":{"sample-lib":"2.3.0-rc.1"}},
            {"approvedVersionLines":{"sample-lib":[3]}},
            {"exactTargets":{}},
            {"policies":{"sample-lib":"keep-current"}},
        ):
            with self.subTest(case=modified), self.assertRaisesRegex(
                ValueError,"DECISION_CONTRACT_INVALID"
            ):
                normalize_decision_contract({**self.intent,**modified})
        with self.assertRaises(ValueError):
            normalize_decision_contract({"exactTargets":{"sample-lib":"2.3.0"}})

    def test_exact_target_admitted_from_real_metadata_not_source_declaration(self):
        row=self.row(spec="1.0.0")
        immutable=self.row(name="immutable-companion",current="7.0.0",spec="7.0.0")
        self.add_metadata("sample-lib",["1.0.0","2.3.0","2.4.0"])
        self.add_metadata("immutable-companion",["7.0.0","8.0.0"])
        rows={"synthetic":[row,immutable]}
        roadmap.apply_decision_contract_targets(rows,self.client)
        self.assertEqual("2.3.0",row.target_default)
        self.assertEqual(roadmap.NO_ACTION,immutable.target_default)
        domain=roadmap._candidate_domain(row,"default",self.client)
        self.assertEqual(["2.3.0","1.0.0"],domain)
        self.assertEqual(["7.0.0"],roadmap._candidate_domain(
            immutable,"default",self.client))
        model=roadmap._build_peer_optimization_model(
            ["sample-lib","immutable-companion"],
            {"sample-lib":row,"immutable-companion":immutable},
            {"sample-lib":domain,"immutable-companion":["7.0.0"]},
            self.client,"default")
        self.assertFalse(model.assignment_issue({
            "sample-lib":"2.3.0","immutable-companion":"7.0.0"}))
        self.assertIsNotNone(model.assignment_issue({
            "sample-lib":"1.0.0","immutable-companion":"7.0.0"}))
        result=solve_z3_exact(model)
        self.assertIn(result.status,("optimal","feasible"))
        self.assertEqual("2.3.0",result.assignment["sample-lib"])
        self.assertEqual("7.0.0",result.assignment["immutable-companion"])

    def test_unavailable_exact_target_is_blocked_without_conjuring_candidate(self):
        row=self.row()
        self.add_metadata("sample-lib",["1.0.0","2.4.0"])
        roadmap.apply_decision_contract_targets({"synthetic":[row]},self.client)
        self.assertEqual(roadmap.NO_ACTION,row.target_default)
        self.assertIn("EXACT_TARGET_UNAVAILABLE",row.compatibility_note)
        self.assertEqual(["1.0.0"],
                         roadmap._candidate_domain(row,"default",self.client))
        self.assertEqual("blocked",roadmap._draft_row_status(
            row,roadmap.NO_ACTION))

    def test_valid_target_recovered_from_authoritative_exact_version_metadata(self):
        row = self.row(spec="1.0.0")
        self.add_metadata("sample-lib", ["1.0.0", "2.4.0"])
        confirmed = {"name": "sample-lib", "version": "2.3.0",
                     "dist": {"tarball": f"{self.REGISTRY}/sample-lib/-/sample-lib-2.3.0.tgz"}}
        self.client.registry_exact_version_manifest.return_value = (
            confirmed, "EXACT_VERSION_METADATA_ADMITTED")
        roadmap.apply_decision_contract_targets({"synthetic": [row]}, self.client)
        self.assertEqual("2.3.0", row.target_default)
        self.assertEqual("1.0.0", row.requested_spec, "source declaration remains baseline evidence")
        self.assertIn("2.3.0", self.client.npm_cache["sample-lib"]["versions"])
        self.assertEqual(["2.3.0", "1.0.0"],
                         roadmap._candidate_domain(row, "default", self.client))

    def test_version_endpoint_guards_identity_origin_and_missing_target(self):
        fetch = roadmap.LiveDataClient.registry_exact_version_manifest
        resp = MagicMock()
        resp.status_code = 200
        good = {"name": "sample-lib", "version": "2.3.0",
                "dist": {"tarball": f"{self.REGISTRY}/sample-lib/-/sample-lib-2.3.0.tgz"}}
        with patch.object(self.client, "_supervised", return_value=resp), patch.object(
                self.client, "_bounded_json", return_value=good):
            found, code = fetch(self.client, "sample-lib", "2.3.0")
        self.assertEqual("EXACT_VERSION_METADATA_ADMITTED", code)
        self.assertEqual("2.3.0", found["version"])
        for malformed, failure in (
            ({**good, "name": "different-name"}, "EXACT_VERSION_IDENTITY_OR_METADATA_INVALID"),
            ({**good, "version": "2.4.0"}, "EXACT_VERSION_IDENTITY_OR_METADATA_INVALID"),
            ({**good, "dist": {"tarball": "https://evil.invalid/hi.tgz"}},
             "EXACT_VERSION_TARBALL_ORIGIN_REJECTED"),
            ({**good, "dist": {}}, "EXACT_VERSION_TARBALL_ORIGIN_REJECTED"),
        ):
            with self.subTest(malformed=malformed):
                with patch.object(self.client, "_supervised", return_value=resp), patch.object(
                        self.client, "_bounded_json", return_value=malformed):
                    target, code = fetch(self.client, "sample-lib", "2.3.0")
                self.assertIsNone(target)
                self.assertEqual(failure, code)
        resp.status_code = 404
        with patch.object(self.client, "_supervised", return_value=resp):
            target, code = fetch(self.client, "sample-lib", "2.3.0")
        self.assertIsNone(target)
        self.assertEqual("EXACT_VERSION_NOT_PUBLISHED", code)
        resp.status_code = 302
        with patch.object(self.client, "_supervised", return_value=resp):
            target, code = fetch(self.client, "sample-lib", "2.3.0")
        self.assertIsNone(target)
        self.assertEqual("EXACT_VERSION_METADATA_UNVERIFIED", code)

    def test_type_and_runtime_blockers_still_disallow_exact_target(self):
        for attr in ("registry_version_type_declarations_ok",
                     "registry_version_runtime_entrypoint_ok"):
            row = self.row()
            self.add_metadata("sample-lib", ["1.0.0", "2.3.0"])
            mock_method = getattr(self.client, attr)
            previous = mock_method.return_value
            mock_method.return_value = "DECLARED_FILE_MISSING"
            try:
                roadmap.apply_decision_contract_targets({"synthetic": [row]}, self.client)
                self.assertEqual(roadmap.NO_ACTION, row.target_default)
                self.assertIn("EXACT_TARGET_UNAVAILABLE", row.compatibility_note)
            finally:
                mock_method.return_value = previous

    def test_incompatible_exact_target_is_unsat_not_silently_replaced(self):
        a=self.row()
        b=self.row(name="immutable-companion",current="7.0.0",spec="7.0.0")
        self.add_metadata("sample-lib",["1.0.0","2.3.0"],
                          peer_on_target={"immutable-companion":"^8.0.0"})
        self.add_metadata("immutable-companion",["7.0.0"])
        rows={"synthetic":[a,b]}
        roadmap.apply_decision_contract_targets(rows,self.client)
        dom={"sample-lib":roadmap._candidate_domain(a,"default",self.client),
             "immutable-companion":roadmap._candidate_domain(b,"default",self.client)}
        model=roadmap._build_peer_optimization_model(
            ["sample-lib","immutable-companion"],
            {"sample-lib":a,"immutable-companion":b},dom,self.client,"default")
        self.assertEqual("unsat",solve_z3_exact(model).status)

    def test_semantic_objective_identity_changes_when_exact_version_changes(self):
        import draft_decision_contract as contract
        a=contract.normalize_decision_contract(self.intent)
        b=contract.normalize_decision_contract({**self.intent,
            "exactTargets":{"sample-lib":"2.4.0"}})
        self.assertNotEqual(a,b)
        self.assertEqual(2,b["version"])
        self.assertNotEqual(json.dumps(a,sort_keys=True),json.dumps(b,sort_keys=True))


if __name__=="__main__":unittest.main()
