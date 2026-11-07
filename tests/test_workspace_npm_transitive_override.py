import unittest

from workspace_npm_transitive_override import propose_npm_transitive_overrides, verify_npm_transitive_override


class WorkspaceNpmTransitiveOverrideTests(unittest.TestCase):
    affected = "node_modules/@app/parent/node_modules/child"
    parent = "node_modules/@app/parent"

    def setUp(self):
        self.packages = {
            "": {"devDependencies": {"@app/parent": "1.0.0", "child": "3.0.0"}},
            self.parent: {"version": "1.0.0", "dependencies": {"child": "^2.0.0"}},
            self.affected: {"version": "2.0.0"},
            "node_modules/child": {"version": "3.0.0"},
        }

    def propose(self, versions=(), overrides=None):
        return propose_npm_transitive_overrides(
            self.packages, overrides or {}, "child", [self.affected], ["<2.0.1"], versions,
        )

    def test_prefers_in_range_candidate_and_flags_existing_major_crossing(self):
        result = self.propose(["2.0.1", "2.0.0", "2.0.2-beta.1"])
        self.assertEqual(result["verification"], "NOT_VERIFIED")
        self.assertEqual([option["version"] for option in result["options"]], ["2.0.1", "3.0.0"])
        first, second = result["options"]
        self.assertEqual(first["overrides"], {"@app/parent@1.0.0": {"child": "2.0.1"}})
        self.assertEqual(first["declaredRange"], "MATCH")
        self.assertEqual(second["declaredRange"], "OUTSIDE_REQUIRES_RUNTIME_REVIEW")
        self.assertTrue(second["alreadyLocked"])

    def test_already_locked_downgrade_is_explicit_and_does_not_hide_forward_options(self):
        self.packages["node_modules/child"]["version"] = "1.9.0"
        result = propose_npm_transitive_overrides(
            self.packages, {}, "child", [self.affected], [">=2 <3"], ["3.0.0", "3.1.0"],
        )
        self.assertEqual(
            [(row["version"], row["versionDirection"], row["alreadyLocked"]) for row in result["options"]],
            [("3.0.0", "UPGRADE", False), ("3.1.0", "UPGRADE", False), ("1.9.0", "DOWNGRADE", True)],
        )

    def test_scoped_existing_rule_is_not_overwritten(self):
        result = self.propose(overrides={"@app/parent@^1": {"other": "2.0.0"}})
        self.assertEqual(result["code"], "OVERRIDE_EXISTING_RULE_REQUIRES_REVIEW")
        self.assertEqual(result["options"], [])

    def test_same_parent_version_with_different_binding_blocks_proposal(self):
        self.packages["node_modules/host/node_modules/@app/parent"] = self.packages[self.parent].copy()
        self.assertEqual(self.propose()["code"], "OVERRIDE_SELECTOR_WOULD_TOUCH_OTHER_COPY")

    def test_hoisted_descendant_consumer_blocks_proposal(self):
        self.packages[self.parent]["dependencies"]["helper"] = "^1.0.0"
        self.packages["node_modules/helper"] = {"version": "1.0.0", "dependencies": {"child": "^3"}}
        self.assertEqual(self.propose()["code"], "OVERRIDE_SELECTOR_WOULD_TOUCH_DESCENDANT")

    def test_resolved_override_is_lock_only_and_rejects_other_binding_changes(self):
        candidate = {path: row.copy() for path, row in self.packages.items() if path != self.affected}
        override = {"@app/parent@1.0.0": {"child": "3.0.0"}}

        def verify():
            return verify_npm_transitive_override(
                self.packages, candidate, {}, override, "child", [self.affected], ["<2.0.1"], "3.0.0",
            )

        result = verify()
        self.assertEqual(result["code"], "OVERRIDE_LOCK_BINDINGS_MATCH")
        self.assertEqual(result["runtime"], "NOT_RUN")
        candidate["node_modules/child"]["integrity"] = "sha512-different"
        self.assertEqual(verify()["code"], "OVERRIDE_UNRELATED_BINDING_CHANGED")
        del candidate["node_modules/child"]["integrity"]
        candidate[self.affected] = self.packages[self.affected].copy()
        stale = verify()
        self.assertEqual(stale["code"], "OVERRIDE_TARGET_BINDING_MISMATCH")
        self.assertEqual((stale["expectedVersion"], stale["actualVersion"]), ("3.0.0", "2.0.0"))

    def test_selected_consumer_splits_shared_provider_without_moving_other_consumer(self):
        shared = "node_modules/child"
        held = "node_modules/held"
        del self.packages[self.affected]
        self.packages[shared]["version"] = "2.0.0"
        self.packages[""] = {"dependencies": {"@app/parent": "1.0.0", "held": "1.0.0"}}
        self.packages[held] = {"version": "1.0.0", "dependencies": {"child": "^2.0.0"}}
        args = ("child", [shared], ["<2.0.1"])
        selected = [self.parent]
        default = propose_npm_transitive_overrides(self.packages, {}, *args, ["2.0.1"])
        self.assertEqual(default["options"][0]["consumerPaths"], [self.parent, held])
        review = propose_npm_transitive_overrides(self.packages, {}, *args, ["2.0.1"],
                                                  selected_consumer_paths=selected)
        option, = review["options"]
        self.assertEqual(option["overrides"], {"@app/parent@1.0.0": {"child": "2.0.1"}})
        self.assertEqual(option["remainingAffectedConsumerCount"], 1)
        self.assertEqual(option["parentSelectorEffect"], "EFFECTIVE_INBOUND_RANGE_MAY_BE_PINNED")

        candidate = {**self.packages, self.affected: {"version": "2.0.1"}}
        def verify():
            return verify_npm_transitive_override(self.packages, candidate, {}, option["overrides"],
                                                  *args, "2.0.1", selected_consumer_paths=selected)

        report = verify()
        self.assertEqual(report["code"], "OVERRIDE_LOCK_BINDINGS_MATCH")
        self.assertEqual(report["remainingAffectedConsumerCount"], 1)
        self.assertEqual(report["parentSelectorEffect"], option["parentSelectorEffect"])
        self.assertEqual(report["otherLockBindings"], "UNCHANGED_DECLARED_LOCK_BINDINGS")
        candidate[shared] = {"version": "2.0.1"}
        self.assertEqual(verify()["code"], "OVERRIDE_UNRELATED_BINDING_CHANGED")

        candidate[shared] = self.packages[shared]
        candidate[held] = {**self.packages[held], "version": "1.1.0"}
        unrelated = verify()
        self.assertEqual(unrelated["code"], "OVERRIDE_OTHER_LOCK_BINDING_CHANGED")
        self.assertEqual(unrelated["dependency"], "held")

        candidate[held] = self.packages[held]
        candidate[self.affected]["dependencies"] = {"new-child": "1.0.0"}
        self.assertEqual(verify()["otherLockBindings"], "NOT_ASSESSED_NON_LEAF")

        invalid = propose_npm_transitive_overrides(self.packages, {}, *args, ["2.0.1"],
                                                   selected_consumer_paths=["node_modules/unrelated"])
        self.assertEqual(invalid["code"], "OVERRIDE_CONSUMER_SELECTION_MISMATCH")

    def test_stale_audit_path_fails_closed(self):
        self.packages[self.affected]["version"] = "2.0.1"
        self.assertEqual(self.propose()["code"], "OVERRIDE_AUDIT_PATH_MISMATCH")
