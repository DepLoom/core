"""Workspace health policy regressions independent of registries and npm."""
import unittest

from peer_solver_model import GroupedCardinality, PackageVariable, PeerOptimizationModel, solve_reference_exact
from peer_solver_z3 import solve_z3_exact
from workspace_health_policy import WorkspaceHealthFact, WorkspaceHealthPolicy, solve_workspace_health
from workspace_peer_model import declaration_id, plan_workspace_upgrade


CLEAN = WorkspaceHealthFact(True, frozenset())


def variable(key, versions=("1.0.0",)):
    return PackageVariable(key, versions[0], versions, tuple((v, (int(i == 0),)) for i, v in enumerate(versions)))


class WorkspaceHealthTests(unittest.TestCase):
    def test_lag_scope_includes_held_and_requires_ceiling(self):
        model = PeerOptimizationModel(tuple(variable(key) for key in ("a", "b", "c")), objective_width=1)
        active = {key: key for key in ("a", "b", "c")}
        facts = {("a", "1.0.0"): CLEAN, ("b", "1.0.0"): CLEAN,
                 ("c", "1.0.0"): WorkspaceHealthFact(False, frozenset())}
        result = solve_workspace_health(model, active, facts, WorkspaceHealthPolicy("yellow", 80), timeout_ms=3000)
        self.assertEqual((result["status"], result["policy"]["lagDenominator"], result["policy"]["lagRequired"]),
                         ("UNSAT_IN_MODELED_DOMAIN", 3, 3))

    def test_constraints_select_a_healthier_candidate_instead_of_failing_after_solve(self):
        model = PeerOptimizationModel((variable("app", ("1.0.0", "2.0.0")), variable("held")), objective_width=1)
        facts = {("react", "1.0.0"): WorkspaceHealthFact(False, frozenset()),
                 ("react", "2.0.0"): CLEAN, ("held", "1.0.0"): CLEAN}
        result = solve_workspace_health(model, {"app": "react", "held": "held"}, facts,
                                        WorkspaceHealthPolicy("yellow", 80), timeout_ms=3000)
        self.assertEqual(result["assignment"], {"app": "2.0.0", "held": "1.0.0"})
        self.assertEqual(result["policy"]["lagConfirmed"], 2)
        self.assertEqual(result["policy"]["finalAudit"], "NOT_RUN")

    def test_one_name_at_multiple_versions_counts_once_per_severity(self):
        model = PeerOptimizationModel((variable("a"), variable("b", ("2.0.0",)), variable("c")), objective_width=1)
        high = WorkspaceHealthFact(True, frozenset("H"))
        facts = {("react", "1.0.0"): high, ("react", "2.0.0"): high, ("other", "1.0.0"): CLEAN}
        active = {"a": "react", "b": "react", "c": "other"}
        yellow = WorkspaceHealthPolicy("yellow", 80)
        result = solve_workspace_health(model, active, facts, yellow, timeout_ms=3000)
        self.assertEqual(result["policy"]["knownBySeverity"]["H"], 1)
        facts["other", "1.0.0"] = high
        result = solve_workspace_health(model, active, facts, yellow, timeout_ms=3000)
        self.assertEqual(result["status"], "UNSAT_IN_MODELED_DOMAIN")

    def test_missing_exact_security_does_not_produce_clean_or_unsat(self):
        model = PeerOptimizationModel((variable("a"), variable("b")), objective_width=1)
        facts = {("a", "1.0.0"): CLEAN, ("b", "2.0.0"): CLEAN}
        result = solve_workspace_health(model, {"a": "a", "b": "b"}, facts,
                                        WorkspaceHealthPolicy("yellow", 80), timeout_ms=3000)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])
        self.assertEqual(result["policy"]["lagDenominator"], 2)

    def test_unknown_lag_keeps_denominator_and_green_requires_all(self):
        keys = ("a", "b", "c", "d", "held")
        model = PeerOptimizationModel(tuple(variable(key) for key in keys), objective_width=1)
        facts = {(key, "1.0.0"): CLEAN for key in keys}
        facts["held", "1.0.0"] = WorkspaceHealthFact(None, frozenset())
        active = {key: key for key in keys}
        yellow = solve_workspace_health(model, active, facts, WorkspaceHealthPolicy("yellow", 80), timeout_ms=3000)
        self.assertEqual(yellow["policy"]["lagConfirmed"], 4)
        self.assertEqual(yellow["policy"]["lagUnknown"], 1)
        green = solve_workspace_health(model, active, facts, WorkspaceHealthPolicy("green", 80, max_moderate=0, max_low=0),
                                       timeout_ms=3000)
        self.assertEqual((green["status"], green["policy"]["lagRequired"]), ("UNKNOWN", 5))

    def test_green_rejects_high_and_counts_combined_severities(self):
        model = PeerOptimizationModel((variable("x"),), objective_width=1)
        active = {"x": "one"}
        green = WorkspaceHealthPolicy("green", 80, max_combined_moderate_low=1)
        for severity in ("H", "ML", "U"):
            with self.subTest(severity=severity):
                facts = {("one", "1.0.0"): WorkspaceHealthFact(True, frozenset(severity))}
                result = solve_workspace_health(model, active, facts, green, timeout_ms=3000)
                self.assertEqual(result["status"], "UNSAT_IN_MODELED_DOMAIN")

    def test_bound_workspace_planner_counts_held_owner_and_classifies_internal_link(self):
        selected = ("packages/app", "dependencies", "demo")
        held = ("packages/legacy", "dependencies", "kept")
        internal = ("packages/app", "dependencies", "internal-ui")
        lock = {
            "node_modules/demo": {"version": "1.0.0"},
            "node_modules/kept": {"version": "1.0.0"},
            "node_modules/internal-ui": {"link": True, "resolved": "packages/ui"},
            "packages/ui": {"version": "1.0.0"},
        }
        packuments = {
            "demo": {"versions": {v: {"name": "demo", "version": v} for v in ("1.0.0", "2.0.0")}},
            "kept": {"versions": {"1.0.0": {"name": "kept", "version": "1.0.0"}}},
        }
        facts = {("demo", "1.0.0"): WorkspaceHealthFact(False, frozenset()),
                 ("demo", "2.0.0"): CLEAN, ("kept", "1.0.0"): CLEAN}
        result = plan_workspace_upgrade(
            lock, {selected: "1.0.0", held: "1.0.0", internal: "1.0.0"},
            {selected: ("1.0.0", "2.0.0")}, {}, packuments,
            health_policy=WorkspaceHealthPolicy("yellow", 80), health_facts=facts,
        )
        self.assertEqual(result["assignment"], {declaration_id(selected): "2.0.0", declaration_id(held): "1.0.0",
                                                declaration_id(internal): "1.0.0"})
        self.assertEqual(result["policy"]["lagDenominator"], 2)
        self.assertEqual(result["policy"]["internalLinkDeclarations"], 1)
        self.assertEqual(result["verification"], "NOT_VERIFIED")

    def test_grouped_constraints_match_independent_reference(self):
        scope = (variable("a", ("1.0.0", "2.0.0")), variable("b", ("1.0.0", "2.0.0")))
        caps = (GroupedCardinality(((("a", "1.0.0"), ("b", "1.0.0")),), "shared", maximum=1),
                GroupedCardinality(((("a", "2.0.0"),), (("b", "2.0.0"),)), "lag", minimum=1))
        model = PeerOptimizationModel(scope, objective_width=1, cardinalities=caps)
        reference, exact = solve_reference_exact(model), solve_z3_exact(model, timeout_ms=3000)
        self.assertEqual(reference.status, "optimal")
        self.assertEqual((exact.assignment, exact.score), (reference.assignment, reference.score))
