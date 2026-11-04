import unittest

from peer_solver_z3 import solve_z3_exact
from workspace_peer_model import (
    WorkspaceCandidate, WorkspaceDomain, WorkspaceModelUnknown,
    compile_workspace_peer_model, declaration_id, workspace_providers_from_lock,
    plan_workspace_from_lock, workspace_domains_from_inputs, plan_workspace_upgrade,
    plan_workspace_from_registry, plan_workspace_in_topology,
)

APP_REACT = ("packages/app", "dependencies", "react")
APP_RENDERER = ("packages/app", "dependencies", "react-dom")
LEGACY_REACT = ("packages/legacy", "dependencies", "react")


class WorkspacePeerModelTests(unittest.TestCase):
    def setUp(self):
        old, new = "18.3.1", "19.0.0"
        react_versions = (WorkspaceCandidate(old, {}), WorkspaceCandidate(new, {}))
        renderer_versions = (WorkspaceCandidate(old, {"react": "^18.3.1"}),
                             WorkspaceCandidate(new, {"react": "^19.0.0"}))
        self.domains = {
            APP_REACT: WorkspaceDomain(old, react_versions, mutable=True, exact_target=new),
            APP_RENDERER: WorkspaceDomain(old, renderer_versions, mutable=True),
            LEGACY_REACT: WorkspaceDomain(old, react_versions),
        }
        self.providers = {(APP_RENDERER, "react"): APP_REACT}

    def test_target_selects_companion_and_preserves_other_owner(self):
        model = compile_workspace_peer_model(self.domains, self.providers)
        result = solve_z3_exact(model)
        self.assertEqual(result.status, "optimal")
        self.assertEqual(result.assignment, {
            declaration_id(APP_REACT): "19.0.0",
            declaration_id(APP_RENDERER): "19.0.0",
            declaration_id(LEGACY_REACT): "18.3.1",
        })

    def test_held_companion_makes_modeled_domain_unsatisfiable(self):
        domain = self.domains[APP_RENDERER]
        self.domains[APP_RENDERER] = WorkspaceDomain(domain.current, domain.candidates)
        result = solve_z3_exact(compile_workspace_peer_model(self.domains, self.providers))
        self.assertEqual(result.status, "unsat")

    def test_node_engine_is_hard_constraint_and_missing_version_is_unknown(self):
        self.domains[APP_RENDERER] = WorkspaceDomain("18.3.1", (
            WorkspaceCandidate("18.3.1", {"react": "^18.3.1"}),
            WorkspaceCandidate("19.0.0", {"react": "^19.0.0"}, engines={"node": ">=24"}),
        ), mutable=True)
        with self.assertRaisesRegex(WorkspaceModelUnknown, "ENGINE_VERSION_UNKNOWN"):
            compile_workspace_peer_model(self.domains, self.providers)
        rejected = compile_workspace_peer_model(self.domains, self.providers,
                                                environment={"node": "22.0.0"})
        self.assertEqual(solve_z3_exact(rejected).status, "unsat")
        accepted = compile_workspace_peer_model(self.domains, self.providers,
                                                environment={"node": "24.18.0"})
        self.assertEqual(solve_z3_exact(accepted).status, "optimal")

    def test_lock_binding_follows_renderer_location_and_abstains_on_shared_slot(self):
        legacy_renderer = ("packages/legacy", "dependencies", "react-dom")
        root_react = (".", "dependencies", "react")
        self.domains[APP_REACT] = WorkspaceDomain("19.0.0", (WorkspaceCandidate("19.0.0", {}),))
        self.domains[legacy_renderer] = WorkspaceDomain("18.3.1", (
            WorkspaceCandidate("18.3.1", {"react": "^18.3.1"}),
        ))
        packages = {
            "node_modules/react": {"version": "19.0.0"},
            "packages/legacy/node_modules/react": {"version": "18.3.1"},
            "packages/legacy/node_modules/react-dom": {"version": "18.3.1"},
        }
        key = (legacy_renderer, "react")
        self.assertEqual(workspace_providers_from_lock(packages, self.domains)[key], LEGACY_REACT)
        packages["node_modules/react-dom"] = packages.pop("packages/legacy/node_modules/react-dom")
        self.assertEqual(workspace_providers_from_lock(packages, self.domains)[key], APP_REACT)
        self.domains[root_react] = self.domains[APP_REACT]
        self.assertNotIn(key, workspace_providers_from_lock(packages, self.domains))

    def test_lock_planner_keeps_separate_slots_and_refuses_implicit_split(self):
        packages = {
            "node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react-dom": {"version": "18.3.1"},
        }
        result = plan_workspace_from_lock(packages, self.domains)
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["assignment"][declaration_id(APP_RENDERER)], "19.0.0")
        self.assertEqual(result["verification"], "NOT_VERIFIED")
        del packages["packages/app/node_modules/react"]
        result = plan_workspace_from_lock(packages, self.domains)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["assignment"])

    def test_lock_and_registry_inputs_keep_owner_scope_and_metadata_identity(self):
        declarations = {key: "18.3.1" for key in self.domains}
        packages = {
            "node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react-dom": {"version": "18.3.1"},
        }
        admitted = {APP_REACT: ("19.0.0",), APP_RENDERER: ("18.3.1", "19.0.0")}
        packuments = {
            "react": {"versions": {v: {"name": "react", "version": v} for v in ("18.3.1", "19.0.0")}},
            "react-dom": {"versions": {
                v: {"name": "react-dom", "version": v, "peerDependencies": {"react": f"^{v}"}}
                for v in ("18.3.1", "19.0.0")
            }},
        }
        exact = {APP_REACT: "19.0.0"}
        result = plan_workspace_upgrade(packages, declarations, admitted, exact, packuments)
        self.assertEqual(result["assignment"][declaration_id(APP_RENDERER)], "19.0.0")
        self.assertEqual(result["assignment"][declaration_id(LEGACY_REACT)], "18.3.1")
        with self.assertRaisesRegex(ValueError, "EXACT_OR_MUTABLE_TARGET_OUTSIDE_DECLARATIONS"):
            workspace_domains_from_inputs(packages, declarations, admitted,
                                          {LEGACY_REACT: "19.0.0"}, packuments)
        del packuments["react-dom"]["versions"]["19.0.0"]
        with self.assertRaisesRegex(WorkspaceModelUnknown, "CANDIDATE_METADATA_MISSING"):
            workspace_domains_from_inputs(packages, declarations, admitted, exact, packuments)

    def test_registry_filters_candidates_and_reads_same_package_once(self):
        class Registry:
            def __init__(self):
                self.calls = []

            def fetch_npm_metadata(self, name):
                self.calls.append(name)
                versions = ("18.3.1", "19.0.0", "19.1.0-beta.0", "19.2.0", "20.0.0")
                return {"versions": {v: {
                    "name": name, "version": v,
                    "peerDependencies": {"react": "^" + v} if name == "react-dom" else {},
                } for v in versions}}

            def registry_tarball_url(self, metadata, version):
                return version

            def registry_artifact_url_allowed(self, url):
                return url != "19.2.0"

        packages = {
            "node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react": {"version": "18.3.1"},
            "packages/app/node_modules/react-dom": {"version": "18.3.1"},
        }
        client = Registry()
        result = plan_workspace_from_registry(
            packages, {key: "18.3.1" for key in self.domains},
            {APP_REACT: (19,), APP_RENDERER: (19,)}, {APP_REACT: "19.0.0"}, client,
        )
        self.assertEqual(result["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(result["assignment"][declaration_id(APP_RENDERER)], "19.0.0")
        self.assertEqual(client.calls, ["react", "react-dom"])

    def test_proposed_layout_enforces_shared_instance_without_global_equality(self):
        separate = ((APP_REACT,), (APP_RENDERER,), (LEGACY_REACT,))
        split = plan_workspace_in_topology(self.domains, self.providers, separate)
        self.assertEqual(split["status"], "SAT_IN_MODELED_DOMAIN")
        self.assertEqual(split["verification"], "NOT_VERIFIED")
        shared = ((APP_REACT, LEGACY_REACT), (APP_RENDERER,))
        merged = plan_workspace_in_topology(self.domains, self.providers, shared)
        self.assertEqual(merged["status"], "UNSAT_IN_MODELED_DOMAIN")
        missing = plan_workspace_in_topology(self.domains, self.providers, separate[:-1])
        self.assertEqual(missing["status"], "UNKNOWN")
        self.assertIsNone(missing["assignment"])

    def test_missing_binding_is_unknown_instead_of_assuming_global_provider(self):
        with self.assertRaisesRegex(WorkspaceModelUnknown, "PEER_PROVIDER_UNKNOWN"):
            compile_workspace_peer_model(self.domains, {})
