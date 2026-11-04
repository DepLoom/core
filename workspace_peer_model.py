"""Compile owner-qualified npm peer constraints for an explicit provider topology.

The caller supplies finite admitted domains and candidate metadata. Provider
bindings are assumptions of the model, not a prediction of npm placement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping

from semantic_version import NpmSpec, Version

from peer_solver_model import PackageVariable, PeerOptimizationModel, RequiresAny, forbidden
from peer_solver_z3 import solve_z3_exact
from resolution_inventory import npm_lock_resolved_instance

Declaration = tuple[str, str, str]


@dataclass(frozen=True)
class WorkspaceCandidate:
    version: str
    peers: Mapping[str, str]
    optional_peers: frozenset[str] = frozenset()
    engines: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkspaceDomain:
    current: str
    candidates: tuple[WorkspaceCandidate, ...]
    mutable: bool = False
    exact_target: str | None = None


@dataclass(frozen=True)
class WorkspaceTopology:
    providers: Mapping[tuple[Declaration, str], Declaration | None]
    instance_groups: tuple[tuple[Declaration, ...], ...]


class WorkspaceModelUnknown(ValueError):
    """Evidence does not suffice to compile a complete modeled domain."""


def declaration_id(declaration: Declaration) -> str:
    return json.dumps(declaration, separators=(",", ":"), ensure_ascii=True)


def workspace_providers_from_lock(
    packages: dict,
    domains: Mapping[Declaration, WorkspaceDomain],
) -> dict[tuple[Declaration, str], Declaration]:
    """Find unique provider variables for a modeled lock layout.

    Follow the consumer package location, not the declaration owner's lookup.
    Absent, linked or ambiguously shared placements are left unbound. These
    bindings describe this lock layout only and cannot verify a future install.
    """
    instances = {}
    by_path = {}
    for declaration, domain in domains.items():
        owner, _, name = declaration
        instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if instance is None or instance[1] != domain.current:
            continue
        path, _ = instance
        entry = packages[path]
        instances[declaration] = entry["resolved"] if entry.get("link") else path
        if not entry.get("link"):
            by_path.setdefault((path, name), []).append(declaration)

    bindings = {}
    for declaration, path in instances.items():
        for peer in sorted({name for item in domains[declaration].candidates for name in item.peers}):
            instance = npm_lock_resolved_instance(packages, peer, path)
            if instance is None:
                continue
            matches = by_path.get((instance[0], peer), ())
            if len(matches) == 1:
                bindings[declaration, peer] = matches[0]
    return bindings


def compile_workspace_peer_model(
    domains: Mapping[Declaration, WorkspaceDomain],
    providers: Mapping[tuple[Declaration, str], Declaration | None],
    *,
    environment: Mapping[str, str] | None = None,
) -> PeerOptimizationModel:
    """Build existing solver IR, failing closed for absent provider evidence.

    A missing binding is unknown. An explicit None is observed absence in
    the modeled topology, allowed only for an optional peer.
    """
    selected = {}
    variables = []
    for key, domain in sorted(domains.items()):
        if domain.exact_target is not None and not domain.mutable and domain.exact_target != domain.current:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_AUTHORITY: {key}")
        candidates = tuple(candidate for candidate in domain.candidates
                           if (domain.mutable or candidate.version == domain.current)
                           and (domain.exact_target is None or candidate.version == domain.exact_target))
        versions = tuple(candidate.version for candidate in candidates)
        if not versions:
            raise WorkspaceModelUnknown(f"CANDIDATE_EVIDENCE_MISSING: {key}")
        if len(set(versions)) != len(versions):
            raise ValueError(f"DUPLICATE_CANDIDATE: {key}")
        selected[key] = candidates
        # Primary objective minimizes changed declarations. Candidate order
        # supplied by the caller determines preference among equal-change plans.
        scores = tuple((version, (int(version == domain.current), -rank))
                       for rank, version in enumerate(versions))
        variables.append(PackageVariable(declaration_id(key), domain.current, versions, scores))

    requirements = []
    engine_constraints = []
    for key, candidates in selected.items():
        for candidate in candidates:
            trigger = (declaration_id(key), candidate.version)
            for engine, spec in sorted(candidate.engines.items()):
                if engine not in {"node", "npm"}:
                    continue
                if environment is None or engine not in environment:
                    raise WorkspaceModelUnknown(f"ENGINE_VERSION_UNKNOWN: {key} -> {engine}")
                try:
                    matches = NpmSpec(spec).match(Version(environment[engine]))
                except ValueError as exc:
                    raise WorkspaceModelUnknown(f"ENGINE_RANGE_UNSUPPORTED: {key} -> {engine}: {spec}") from exc
                if not matches:
                    engine_constraints.append(forbidden(
                        (trigger,), reason=f"{key}@{candidate.version} requires {engine}@{spec}",
                        provenance="workspace-modeled-engine-range",
                    ))
            for peer, spec in sorted(candidate.peers.items()):
                binding = (key, peer)
                if binding not in providers:
                    raise WorkspaceModelUnknown(f"PEER_PROVIDER_UNKNOWN: {key}@{candidate.version} -> {peer}")
                provider = providers[binding]
                if provider is None:
                    if peer in candidate.optional_peers:
                        continue
                    # An empty requirement against the trigger's own variable
                    # makes this exact candidate infeasible.
                    provider, allowed = key, ()
                else:
                    if provider not in selected:
                        raise WorkspaceModelUnknown(f"PEER_PROVIDER_OUTSIDE_MODEL: {key} -> {peer}")
                    if provider[2] != peer:
                        raise ValueError(f"PEER_PROVIDER_NAME_MISMATCH: {key} -> {peer}")
                    try:
                        npm_range = NpmSpec(spec)
                        allowed = tuple(item.version for item in selected[provider]
                                        if npm_range.match(Version(item.version)))
                    except ValueError as exc:
                        raise WorkspaceModelUnknown(f"PEER_RANGE_UNSUPPORTED: {key} -> {peer}: {spec}") from exc
                requirements.append(RequiresAny(
                    trigger, declaration_id(provider), allowed,
                    reason=f"{key}@{candidate.version} requires {peer}@{spec} via {provider}",
                    provenance="workspace-modeled-peer-range",
                ))
    return PeerOptimizationModel(tuple(variables), constraints=tuple(engine_constraints),
                                 requirements=tuple(requirements), objective_width=2)


def workspace_domains_from_inputs(
    packages: dict,
    declarations: Mapping[Declaration, str],
    admitted_versions: Mapping[Declaration, tuple[str, ...]],
    exact_targets: Mapping[Declaration, str],
    packuments: Mapping[str, dict],
) -> dict[Declaration, WorkspaceDomain]:
    """Bind admitted candidate metadata and lock versions to declaration owners.

    Only keys explicitly admitted by the caller are mutable. Candidate lists
    must have passed registry origin, stability and version-line policy upstream.
    """
    if not admitted_versions.keys() <= declarations.keys() or not exact_targets.keys() <= admitted_versions.keys():
        raise ValueError("EXACT_OR_MUTABLE_TARGET_OUTSIDE_DECLARATIONS")
    domains = {}
    for key in declarations:
        owner, _, name = key
        current = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if current is None:
            raise WorkspaceModelUnknown(f"WORKSPACE_SLOT_UNPROVEN: {key}")
        path, version = current
        mutable = key in admitted_versions
        choices = admitted_versions.get(key, (version,))
        exact = exact_targets.get(key)
        if exact is not None and exact not in choices:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_ADMITTED_DOMAIN: {key}")
        entry = packages[path]
        if entry.get("link"):
            if mutable:
                raise ValueError(f"WORKSPACE_LINK_TARGET_NOT_MUTABLE: {key}")
            metadata = {version: packages[entry["resolved"]]}
        else:
            metadata = packuments.get(name, {}).get("versions", {})

        candidates = []
        for choice in choices:
            item = metadata.get(choice)
            if not isinstance(item, dict) or item.get("version") != choice:
                raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_MISSING: {key}@{choice}")
            if not entry.get("link") and item.get("name") != name:
                raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_IDENTITY_MISMATCH: {key}@{choice}")
            peers = item.get("peerDependencies", {})
            peer_meta = item.get("peerDependenciesMeta", {})
            engines = item.get("engines", {})
            if (not all(isinstance(value, dict) for value in (peers, peer_meta, engines))
                    or any(not isinstance(value, str) for value in (*peers.values(), *engines.values()))
                    or any(not isinstance(value, dict) for value in peer_meta.values())):
                raise WorkspaceModelUnknown(f"CANDIDATE_METADATA_INVALID: {key}@{choice}")
            optional = frozenset(peer for peer, flags in peer_meta.items() if flags.get("optional") is True)
            candidates.append(WorkspaceCandidate(choice, peers, optional, engines))
        domains[key] = WorkspaceDomain(version, tuple(candidates), mutable, exact)
    return domains


def plan_workspace_from_lock(
    packages: dict,
    domains: Mapping[Declaration, WorkspaceDomain],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
) -> dict:
    """Plan conditionally on observed slots; an npm re-layout remains unmodeled."""
    result = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
              "topology": "OBSERVED_LOCK_LAYOUT", "assignment": None}
    try:
        if not domains:
            raise WorkspaceModelUnknown("WORKSPACE_DOMAIN_EMPTY")
        instances = {}
        for key, domain in domains.items():
            owner, _, name = key
            instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
            if instance is None or instance[1] != domain.current or (domain.mutable and packages[instance[0]].get("link")):
                raise WorkspaceModelUnknown(f"WORKSPACE_SLOT_UNPROVEN: {key}")
            instances.setdefault(instance[0], []).append(key)
        model = compile_workspace_peer_model(
            domains, workspace_providers_from_lock(packages, domains), environment=environment)
        variables = model.package_map()
        for path, keys in instances.items():
            if len(keys) > 1:
                candidate_sets = {variables[declaration_id(key)].domain for key in keys}
                if len(candidate_sets) != 1 or len(next(iter(candidate_sets))) != 1:
                    raise WorkspaceModelUnknown(f"SHARED_SLOT_RELAYOUT_UNMODELED: {path}")
    except WorkspaceModelUnknown as exc:
        return {**result, "status": "UNKNOWN", "reason": str(exc)}

    return _solve_workspace_model(model, result, timeout_ms, excluded_assignments)


def plan_workspace_in_topology(
    domains: Mapping[Declaration, WorkspaceDomain],
    providers: Mapping[tuple[Declaration, str], Declaration | None],
    instance_groups: tuple[tuple[Declaration, ...], ...],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
) -> dict:
    """Check a proposed partition into npm instances before native resolution."""
    result = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
              "topology": "PROPOSED_INSTANCE_LAYOUT", "assignment": None}
    members = [key for group in instance_groups for key in group]
    if (not domains or set(members) != domains.keys() or len(members) != len(domains)
            or any(not group or len({key[2] for key in group}) != 1 for group in instance_groups)):
        return {**result, "status": "UNKNOWN", "reason": "WORKSPACE_INSTANCE_PARTITION_UNPROVEN"}
    try:
        model = compile_workspace_peer_model(domains, providers, environment=environment)
    except WorkspaceModelUnknown as exc:
        return {**result, "status": "UNKNOWN", "reason": str(exc)}

    variables = model.package_map()
    requirements = list(model.requirements)
    for group in instance_groups:
        first, *others = sorted(map(declaration_id, group))
        for other in others:
            for version in variables[first].domain:
                allowed = (version,) if version in variables[other].domain else ()
                requirements.append(RequiresAny(
                    (first, version), other, allowed,
                    reason=f"{first} and {other} share one proposed instance",
                    provenance="workspace-proposed-instance",
                ))
    model = PeerOptimizationModel(model.packages, model.constraints, tuple(requirements), model.objective_width)
    return _solve_workspace_model(model, result, timeout_ms, excluded_assignments)


def _solve_workspace_model(model, result, timeout_ms, excluded_assignments):
    if excluded_assignments:
        model = model.with_constraints(
            forbidden(model.assignment_key(vector), reason="Previously tried complete candidate",
                      provenance="workspace-request-enumeration")
            for vector in excluded_assignments
        )
    solved = solve_z3_exact(model, timeout_ms=timeout_ms)
    if solved.status == "optimal" and solved.assignment is not None:
        return {**result, "status": "SAT_IN_MODELED_DOMAIN", "assignment": solved.assignment}
    if solved.status == "unsat":
        return {**result, "status": "UNSAT_IN_MODELED_DOMAIN"}
    return {**result, "status": "UNKNOWN", "reason": solved.detail or solved.status}


def plan_workspace_from_registry(
    packages: dict,
    declarations: Mapping[Declaration, str],
    approved_lines: Mapping[Declaration, tuple[int, ...]],
    exact_targets: Mapping[Declaration, str],
    client,
    *,
    environment: Mapping[str, str] | None = None,
    topology: WorkspaceTopology | None = None,
    candidate_limit: int = 32,
    timeout_ms: int = 30_000,
) -> dict:
    """Read deduplicated packuments through the existing Core registry client."""
    from dependency_live_roadmap_generator import DraftBudgetExceeded, RegistryInfrastructureError

    if not approved_lines.keys() <= declarations.keys() or not exact_targets.keys() <= approved_lines.keys():
        raise ValueError("EXACT_OR_MUTABLE_TARGET_OUTSIDE_DECLARATIONS")
    if not 1 <= candidate_limit <= 128:
        raise ValueError("INVALID_WORKSPACE_CANDIDATE_LIMIT")
    for key, target in exact_targets.items():
        version = Version(target)
        if version.prerelease or version.major not in approved_lines[key]:
            raise ValueError(f"EXACT_TARGET_OUTSIDE_APPROVED_LINES: {key}")

    unknown = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
               "topology": "PROPOSED_INSTANCE_LAYOUT" if topology else "OBSERVED_LOCK_LAYOUT", "status": "UNKNOWN", "assignment": None}
    packuments = {}
    admitted = {}
    for key in sorted(declarations):
        owner, _, name = key
        current = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if current is None:
            return {**unknown, "reason": f"WORKSPACE_SLOT_UNPROVEN: {key}"}
        path, current_version = current
        if packages[path].get("link"):
            if key in approved_lines:
                raise ValueError(f"WORKSPACE_LINK_TARGET_NOT_MUTABLE: {key}")
            continue
        if name not in packuments:
            try:
                packument = client.fetch_npm_metadata(name)
            except (RegistryInfrastructureError, DraftBudgetExceeded):
                return {**unknown, "reason": f"REGISTRY_METADATA_UNAVAILABLE: {name}"}
            if not isinstance(packument, dict) or not isinstance(packument.get("versions"), dict):
                return {**unknown, "reason": f"REGISTRY_METADATA_UNAVAILABLE: {name}"}
            packuments[name] = packument
        if key not in approved_lines:
            continue
        packument = packuments[name]
        current_semver = Version(current_version)
        candidates = []
        versions = (exact_targets[key],) if key in exact_targets else packument["versions"]
        for value in versions:
            if value == current_version and key not in exact_targets:
                candidates.append(Version(value))
                continue
            try:
                version = Version(value)
            except ValueError:
                continue
            if version.prerelease or version < current_semver or version.major not in approved_lines[key]:
                continue
            if not isinstance(packument["versions"].get(value), dict):
                continue
            url = client.registry_tarball_url(packument, value)
            if url and client.registry_artifact_url_allowed(url):
                candidates.append(version)
        if not candidates or len(candidates) > candidate_limit:
            return {**unknown, "reason": f"WORKSPACE_CANDIDATE_DOMAIN_UNAVAILABLE: {key}"}
        admitted[key] = tuple(str(value) for value in sorted(candidates, reverse=True))

    return plan_workspace_upgrade(packages, declarations, admitted, exact_targets, packuments,
                                  environment=environment, topology=topology, timeout_ms=timeout_ms)


def plan_workspace_upgrade(
    packages: dict,
    declarations: Mapping[Declaration, str],
    admitted_versions: Mapping[Declaration, tuple[str, ...]],
    exact_targets: Mapping[Declaration, str],
    packuments: Mapping[str, dict],
    *,
    environment: Mapping[str, str] | None = None,
    topology: WorkspaceTopology | None = None,
    timeout_ms: int = 30_000,
    excluded_assignments: tuple[Mapping[str, str], ...] = (),
) -> dict:
    """Use a bounded metadata snapshot to plan under the observed npm lock layout."""
    try:
        domains = workspace_domains_from_inputs(
            packages, declarations, admitted_versions, exact_targets, packuments)
    except WorkspaceModelUnknown as exc:
        return {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
                "topology": "PROPOSED_INSTANCE_LAYOUT" if topology else "OBSERVED_LOCK_LAYOUT", "status": "UNKNOWN",
                "reason": str(exc), "assignment": None}
    if topology is not None:
        return plan_workspace_in_topology(domains, topology.providers, topology.instance_groups,
                                          environment=environment, timeout_ms=timeout_ms,
                                          excluded_assignments=excluded_assignments)
    return plan_workspace_from_lock(packages, domains, environment=environment,
                                    timeout_ms=timeout_ms, excluded_assignments=excluded_assignments)
