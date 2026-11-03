"""Local, non-mutating admission of Draft recommendations for publication.

Candidate observations are not recommendations until planning completes. This
boundary never fetches evidence, solves a model or substitutes a requested target.
"""
from __future__ import annotations
import dataclasses
import json
from typing import Any, Callable, Mapping, Sequence, TypeVar
from draft_decision_contract import contract_from_snapshot, package_is_mutable, version_line_allowed

T = TypeVar("T")


def guard_draft_publication(
    rows_by_project: Mapping[str, Sequence[T]],
    snapshot: Mapping[str, Any],
    *,
    planning_complete: bool,
    no_action: str,
    is_action: Callable[[str], bool],
) -> tuple[dict[str, list[T]], dict[str, Any]]:
    contract = contract_from_snapshot(snapshot)
    raw = snapshot.get("intentJson") or {}
    intent = raw if isinstance(raw, dict) else json.loads(raw)
    policies = intent.get("policies") or {}
    policies = policies if isinstance(policies, dict) else {}
    guarded: dict[str, list[T]] = {}
    issues: list[dict[str, Any]] = []
    changed_projects: list[str] = []
    for project, rows in rows_by_project.items():
        published = []
        for row in rows:
            targets = {mode: getattr(row, "target_" + mode) for mode in ("default", "yellow", "green")}
            keep = (not package_is_mutable(row.name, contract)
                    or str(policies.get(row.name) or "").strip().lower() == "keep-current")
            excluded = bool(row.scope_excluded)
            active = not (excluded or row.planner_deferred)
            code = ""
            if keep or excluded:
                if active and any(is_action(v) and v != row.current_version for v in targets.values()):
                    code = "OWNER_KEEP_CURRENT"
                changes = {"target_" + mode: no_action for mode in targets}
                if keep and not excluded:
                    changes["planner_deferred"] = True
                    changes["planner_deferred_reason"] = row.planner_deferred_reason or "Owner contract: keep current version"
            elif active and not planning_complete:
                code = "PLANNING_NOT_COMPLETED"
                changes = {"target_" + mode: no_action for mode in targets}
                changes["draft_planning_unknown"] = "Planning did not complete; observed candidates are not approved recommendations"
            elif active and any(is_action(v) and not version_line_allowed(row.name, row.current_version, v, contract)
                                for v in targets.values()):
                code = "OWNER_TARGET_NOT_ALLOWED"
                changes = {"target_" + mode: no_action for mode in targets}
                changes["draft_planning_unknown"] = "Observed target does not satisfy the owner contract; permitted assignment remains unresolved"
            else:
                changes = {}
            if changes and any(getattr(row, key) != value for key, value in changes.items()):
                row = dataclasses.replace(row, **changes)
                if project not in changed_projects:
                    changed_projects.append(project)
            if code:
                issues.append({"project": project, "package": row.name, "kind": row.kind,
                               "code": code, "observedTargets": targets})
            published.append(row)
        guarded[project] = published
    return guarded, {"schemaVersion": 1, "planningComplete": planning_complete,
                     "issues": issues, "changedProjects": changed_projects}
