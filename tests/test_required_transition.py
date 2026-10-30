from __future__ import annotations

import unittest

from peer_solver_model import PackageVariable, PeerOptimizationModel, forbidden
from peer_solver_transition import refine_transition_safe_groups
from peer_solver_z3 import solve_z3_exact


def package(name: str, current: str = "1.0.0", upgraded: str = "2.0.0") -> PackageVariable:
    return PackageVariable(
        name=name, current_version=current, domain=(upgraded, current),
        scores=((upgraded, (1,)), (current, (0,))),
    )


class RequiredUpdateTransitionTests(unittest.TestCase):
    def test_required_is_final_only_and_z3_enforces_it(self):
        current = {"router": "1.0.0"}
        target = {"router": "2.0.0"}
        model = PeerOptimizationModel(
            packages=(package("router"),),
            constraints=(forbidden(
                [("router", "1.0.0")],
                reason="USER_BASELINE_REQUIRED_UPDATE: router must change",
                provenance="baseline-intent",
            ),),
            objective_width=1,
        )
        self.assertIn("USER_BASELINE_REQUIRED_UPDATE", model.assignment_issue(current))
        self.assertEqual("", model.assignment_issue(target))
        solved = solve_z3_exact(model)
        self.assertEqual("optimal", solved.status, solved.detail)
        self.assertEqual(target, solved.assignment)
        transition = refine_transition_safe_groups(model, current, solved.assignment)
        self.assertTrue(transition.safe, transition.unresolved)
        self.assertEqual((("router",),), transition.groups)

    def test_exact_target_is_final_only_and_still_hard_in_z3(self):
        # Regression for real Chalk: a correct final-only version pin cannot
        # invalidate the original installed state in transition analysis.
        current = {"router": "1.0.0"}
        final = {"router": "2.0.0"}
        model = PeerOptimizationModel(
            packages=(package("router"),),
            constraints=(forbidden(
                [("router", "1.0.0")],
                reason="USER_EXACT_TARGET: router must be 2.0.0",
                provenance="user-exact-target",
            ),),
            objective_width=1,
        )
        self.assertIn("USER_EXACT_TARGET", model.assignment_issue(current))
        self.assertEqual("", model.assignment_issue(final))
        solved = solve_z3_exact(model)
        self.assertEqual("optimal", solved.status, solved.detail)
        self.assertEqual(final, solved.assignment)
        transition = refine_transition_safe_groups(model, current, final)
        self.assertTrue(transition.safe, transition.unresolved)
        self.assertEqual((("router",),), transition.groups)

    def test_exact_target_does_not_bypass_peer_or_environment_guards(self):
        current = {"router": "1.0.0", "adapter": "1.0.0"}
        final = {"router": "2.0.0", "adapter": "2.0.0"}
        constraint = forbidden(
            [("router", "1.0.0")],
            reason="USER_EXACT_TARGET: router must be 2.0.0",
            provenance="user-exact-target",
        )
        peer = forbidden(
            [("router", "2.0.0"), ("adapter", "1.0.0")],
            reason="PEER_CONFLICT: adapter 1 requires router 1",
            provenance="peer-range-current-source",
        )
        model = PeerOptimizationModel(
            packages=(package("router"), package("adapter")),
            constraints=(constraint, peer),
            objective_width=1,
        )
        transition = refine_transition_safe_groups(model, current, final)
        self.assertTrue(transition.safe, transition.unresolved)
        self.assertEqual((("adapter", "router"),), transition.groups)
        bad_target = PeerOptimizationModel(
            packages=model.packages,
            constraints=model.constraints + (forbidden(
                [("router", "2.0.0")],
                reason="PROJECT_NODE_ENGINE_CONFLICT: target requires a newer Node",
                provenance="project-environment",
            ),),
            objective_width=1,
        )
        self.assertEqual("unsat", solve_z3_exact(bad_target).status)
        invalid = refine_transition_safe_groups(bad_target, current, final)
        self.assertFalse(invalid.safe)
        self.assertTrue(any("INVALID_TARGET_ENDPOINT" in reason for reason in invalid.unresolved))

    def test_spoofed_exact_reason_without_provenance_is_not_ignored(self):
        current = {"router": "1.0.0"}
        final = {"router": "2.0.0"}
        model = PeerOptimizationModel(
            packages=(package("router"),),
            constraints=(forbidden(
                [("router", "1.0.0")],
                reason="USER_EXACT_TARGET: router must move",
                provenance="project-environment",
            ),),
            objective_width=1,
        )
        result = refine_transition_safe_groups(model, current, final)
        self.assertFalse(result.safe)
        self.assertTrue(any("INVALID_CURRENT_ENDPOINT" in reason for reason in result.unresolved))

    def test_source_peer_constraint_still_couples_transaction(self):
        current = {"router": "1.0.0", "adapter": "1.0.0"}
        target = {"router": "2.0.0", "adapter": "2.0.0"}
        model = PeerOptimizationModel(
            packages=(package("router"), package("adapter")),
            constraints=(
                forbidden([("router", "1.0.0")],
                          reason="USER_BASELINE_REQUIRED_UPDATE: router must change"),
                forbidden([("adapter", "1.0.0"), ("router", "2.0.0")],
                          reason="PEER_CONFLICT: adapter v1 requires router v1",
                          provenance="peer-range-current-source"),
            ),
            objective_width=1,
        )
        result = refine_transition_safe_groups(model, current, target)
        self.assertTrue(result.safe, result.unresolved)
        self.assertEqual((("adapter", "router"),), result.groups)
        self.assertEqual("", model.assignment_issue(target))

    def test_real_invalid_target_remains_invalid(self):
        current = {"router": "1.0.0", "adapter": "1.0.0"}
        target = {"router": "2.0.0", "adapter": "2.0.0"}
        model = PeerOptimizationModel(
            packages=(package("router"), package("adapter")),
            constraints=(
                forbidden([("router", "1.0.0")],
                          reason="USER_BASELINE_REQUIRED_UPDATE: router must change"),
                forbidden([("router", "2.0.0"), ("adapter", "2.0.0")],
                          reason="PEER_CONFLICT: invalid final tuple"),
            ),
            objective_width=1,
        )
        result = refine_transition_safe_groups(model, current, target)
        self.assertFalse(result.safe)
        self.assertTrue(any("INVALID_TARGET_ENDPOINT" in item for item in result.unresolved))
        self.assertIn("PEER_CONFLICT", model.assignment_issue(target))

    def test_keep_current_and_required_are_not_silently_compatible(self):
        model = PeerOptimizationModel(
            packages=(package("router"),),
            constraints=(
                forbidden([("router", "1.0.0")], reason="USER_BASELINE_REQUIRED_UPDATE: router"),
                forbidden([("router", "2.0.0")], reason="USER_BASELINE_KEEP_CURRENT: router"),
            ),
            objective_width=1,
        )
        self.assertEqual("unsat", solve_z3_exact(model).status)


if __name__ == "__main__":
    unittest.main()
