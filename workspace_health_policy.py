"""Workspace health constraints over exact candidate-version evidence."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from time import monotonic
from typing import Mapping

from peer_solver_model import GroupedCardinality, PeerOptimizationModel, forbidden
from peer_solver_z3 import solve_z3_exact

_SEVERITIES = frozenset("CHMLU")


@dataclass(frozen=True)
class WorkspaceHealthFact:
    lag_ok: bool | None
    severities: frozenset[str] | None


@dataclass(frozen=True)
class WorkspaceHealthPolicy:
    target: str
    min_lag_ok_pct: int
    max_critical: int = 0
    max_high: int = 1
    max_moderate: int | None = None
    max_low: int | None = None
    max_combined_moderate_low: int | None = None

    def ratio(self) -> tuple[int, int]:
        from dependency_live_roadmap_generator import health_green_ratio

        return health_green_ratio() if self.target == "green" else (self.min_lag_ok_pct, 100)

    def limits(self) -> dict[str, int]:
        if (self.target not in {"yellow", "green"} or type(self.min_lag_ok_pct) is not int
                or not 0 <= self.min_lag_ok_pct <= 100):
            raise ValueError("INVALID_WORKSPACE_HEALTH_POLICY")
        caps = {"C": self.max_critical, "H": self.max_high, "M": self.max_moderate,
                "L": self.max_low, "U": 0, "M+L": self.max_combined_moderate_low}
        if any(value is not None and (type(value) is not int or value < 0) for value in caps.values()):
            raise ValueError("INVALID_WORKSPACE_HEALTH_POLICY")
        if self.max_critical != 0 or self.max_high is None:
            raise ValueError("INVALID_WORKSPACE_HEALTH_POLICY")
        if self.target == "green":
            caps["H"] = 0
            if caps["M"] is None and caps["L"] is None and caps["M+L"] is None:
                raise ValueError("WORKSPACE_GREEN_MODERATE_LOW_POLICY_MISSING")
        return {key: value for key, value in caps.items() if value is not None}


def _constraints(model, names, facts, required, limits, *, assume_unknown):
    lag = defaultdict(list)
    severity = {label: defaultdict(list) for label in limits}
    unknown = []
    for variable in model.packages:
        name = names.get(variable.name)
        if name is None:
            continue
        for version in variable.domain:
            literal = (variable.name, version)
            evidence = facts.get((name, version), WorkspaceHealthFact(None, None))
            if evidence.lag_ok is True or (evidence.lag_ok is None and assume_unknown):
                lag[variable.name].append(literal)
            if evidence.severities is None:
                if not assume_unknown:
                    unknown.append(forbidden((literal,), reason="WORKSPACE_SECURITY_EVIDENCE_UNKNOWN",
                                             provenance="workspace-exact-security-evidence"))
                continue
            for label in limits:
                if evidence.severities.intersection(label.split("+")):
                    # The combined cap counts a package once per severity,
                    # matching the sum of the two unique-name counts.
                    for member in evidence.severities.intersection(label.split("+")):
                        severity[label][name, member].append(literal)
    cardinalities = [GroupedCardinality(tuple(map(tuple, lag.values())), "WORKSPACE_LAG_SHORTFALL",
                                       minimum=required)]
    cardinalities.extend(
        GroupedCardinality(tuple(map(tuple, groups.values())), f"WORKSPACE_SECURITY_{label}_CAP",
                           maximum=limits[label])
        for label, groups in severity.items()
    )
    return replace(model.with_constraints(unknown), cardinalities=(*model.cardinalities, *cardinalities))


def solve_workspace_health(
    model: PeerOptimizationModel, active_names: Mapping[str, str],
    facts: Mapping[tuple[str, str], WorkspaceHealthFact], policy: WorkspaceHealthPolicy,
    *, timeout_ms: int,
) -> dict:
    """Solve within finite admitted domains; distinguish insufficient evidence from a proven block."""
    from dependency_live_roadmap_generator import required_ratio_count

    if not active_names or not active_names.keys() <= model.package_map().keys():
        raise ValueError("INVALID_WORKSPACE_POLICY_SCOPE")
    if type(timeout_ms) is not int or timeout_ms < 1:
        raise ValueError("INVALID_WORKSPACE_POLICY_DEADLINE")
    if any((fact.lag_ok is not None and type(fact.lag_ok) is not bool)
           or (fact.severities is not None and
               (not isinstance(fact.severities, frozenset) or not fact.severities <= _SEVERITIES))
           for fact in facts.values()):
        raise ValueError("INVALID_WORKSPACE_POLICY_EVIDENCE")

    deadline = monotonic() + timeout_ms / 1000
    limits = policy.limits()
    denominator = len(active_names)
    required = required_ratio_count(denominator, policy.ratio())
    summary = {"targetLevel": policy.target, "targetScope": "ACTIVE_WORKSPACE_DECLARATIONS",
               "lagDenominator": denominator, "lagRequired": required, "severityLimits": limits,
               "securityUnit": "UNIQUE_PACKAGE_NAMES_PER_SEVERITY",
               "authority": "DECLARED_DOMAIN_PLANNING_ONLY", "finalAudit": "NOT_RUN"}

    def solve(assume_unknown):
        constrained = _constraints(model, active_names, facts, required, limits, assume_unknown=assume_unknown)
        remaining = int((deadline - monotonic()) * 1000)
        return solve_z3_exact(constrained, timeout_ms=remaining) if remaining >= 1 else None

    proven = solve(False)
    if proven is not None and proven.status == "optimal" and proven.assignment is not None:
        selected = {key: facts.get((name, proven.assignment[key]), WorkspaceHealthFact(None, None))
                    for key, name in active_names.items()}
        unique = {level: {active_names[key] for key, fact in selected.items()
                          if level in (fact.severities or ())} for level in sorted(_SEVERITIES)}
        return {"status": "SAT_IN_MODELED_DOMAIN", "assignment": proven.assignment,
                "policy": {**summary, "status": "FEASIBLE_IN_MODELED_DOMAIN",
                           "lagConfirmed": sum(fact.lag_ok is True for fact in selected.values()),
                           "lagUnknown": sum(fact.lag_ok is None for fact in selected.values()),
                           "securityUnknown": 0,
                           "knownBySeverity": {level: len(names) for level, names in unique.items()}}}

    if proven is not None and proven.status == "unsat":
        optimistic = solve(True)
        if optimistic is not None and optimistic.status == "unsat":
            return {"status": "UNSAT_IN_MODELED_DOMAIN", "assignment": None,
                    "policy": {**summary, "status": "BLOCKED_IN_MODELED_DOMAIN"}}
        code = ("WORKSPACE_POLICY_EVIDENCE_INCOMPLETE" if optimistic is not None and optimistic.status == "optimal"
                else "WORKSPACE_POLICY_SOLVE_INCONCLUSIVE")
    else:
        code = "WORKSPACE_POLICY_SOLVE_INCONCLUSIVE"
    return {"status": "UNKNOWN", "assignment": None, "reason": code,
            "policy": {**summary, "status": "UNKNOWN"}}
