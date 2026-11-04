"""Bound the npm lock delta to declared targets and authorized placement repair."""
from __future__ import annotations

from collections import deque

from resolution_inventory import npm_lock_resolved_instance

INSTALL_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def peer_context(consumer: str) -> str:
    parent, separator, _ = ("/" + consumer).rpartition("/node_modules/")
    return parent.strip("/") if separator else consumer


def _edges(packages: dict, consumer: str) -> dict:
    entry = packages.get(consumer, {})
    edges = {}
    for section in (*INSTALL_SECTIONS, "peerDependencies"):
        for name, spec in entry.get(section, {}).items():
            context = peer_context(consumer) if section == "peerDependencies" else consumer
            provider = npm_lock_resolved_instance(packages, name, context)
            edges[section, name] = (spec, provider)
    return edges


def _instance(packages, declaration):
    owner, _, name = declaration
    return npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)


def _artifact(entry):
    return tuple(entry.get(key) for key in ("version", "resolved", "integrity", "link"))


def check_workspace_lock_delta(baseline, candidate, manifest_deltas, assignment, changed, reauthored):
    """Reject unrelated node or edge churn using both observed lock graphs.

    A target can affect descendants along changed package rows and provider
    bindings. A retained node with an unchanged binding does not expand scope.
    The closure is conservative and does not prove minimal npm placement.
    """
    if baseline.keys() != candidate.keys() or any(
        baseline[key] != candidate[key] for key in baseline if key != "packages"
    ):
        return {"status": "RESOLUTION_FAILED", "code": "LOCK_ENVELOPE_CHANGED"}
    before, after = baseline["packages"], candidate["packages"]
    if max(len(before), len(after)) > 20000:
        return {"status": "UNKNOWN", "code": "LOCK_DELTA_ENTRY_LIMIT"}

    owners = {"" if owner == "." else owner for owner, _, _ in assignment} | {""}
    owners.update(path for path in before if "node_modules" not in path.split("/"))
    for owner in sorted(owners):
        expected = dict(before[owner])
        for section, replacements in manifest_deltas.get(owner, {}).items():
            expected[section] = {**expected.get(section, {}), **replacements}
        if after.get(owner) != expected:
            return {"status": "RESOLUTION_FAILED", "code": "LOCK_OWNER_RECORD_CHANGED", "path": owner}
    if {path for path in after if "node_modules" not in path.split("/")} != owners:
        return {"status": "RESOLUTION_FAILED", "code": "LOCK_WORKSPACE_MEMBERSHIP_CHANGED"}

    seeds = set(changed)
    if reauthored is not None:
        seeds.add(reauthored)
    impacted = set()
    for declaration in sorted(assignment):
        left, right = (_instance(graph, declaration) for graph in (before, after))
        if left is None or right is None:
            return {"status": "UNKNOWN", "code": "LOCK_DELTA_INSTANCE_UNAVAILABLE"}
        if declaration not in changed and _artifact(before[left[0]]) != _artifact(after[right[0]]):
            return {"status": "RESOLUTION_FAILED", "code": "HELD_LOCK_ARTIFACT_CHANGED",
                    "declaration": list(declaration)}
        if declaration in seeds:
            impacted.update((left[0], right[0]))

    nodes = before.keys() | after.keys()
    delta = {path for path in nodes - owners if before.get(path) != after.get(path)}
    for path in sorted(delta):
        if before.get(path, {}).get("link") or after.get(path, {}).get("link"):
            return {"status": "RESOLUTION_FAILED", "code": "LOCK_WORKSPACE_LINK_CHANGED", "path": path}
    queue = deque(sorted(impacted))
    while queue:
        consumer = queue.popleft()
        if consumer in owners:
            continue
        left, right = (_edges(graph, consumer) for graph in (before, after))
        for key in left.keys() | right.keys():
            left_spec, left_provider = left.get(key, (None, None))
            right_spec, right_provider = right.get(key, (None, None))
            left_path = left_provider[0] if left_provider else None
            right_path = right_provider[0] if right_provider else None
            if (_artifact(before.get(consumer, {})) == _artifact(after.get(consumer, {}))
                    and (left_spec, left_path) == (right_spec, right_path)):
                continue
            for provider in (left_provider, right_provider):
                if provider is not None and provider[0] not in impacted:
                    impacted.add(provider[0])
                    queue.append(provider[0])
    outside = sorted(delta - impacted)
    if outside:
        return {"status": "RESOLUTION_FAILED", "code": "LOCK_UNRELATED_NODE_DELTA",
                "path": outside[0], "unrelatedCount": len(outside)}

    edge_changes = 0
    for consumer in sorted(nodes):
        left, right = (_edges(graph, consumer) for graph in (before, after))
        for key in sorted(left.keys() | right.keys()):
            if left.get(key) == right.get(key):
                continue
            providers = {edge[1][0] for edge in (left.get(key), right.get(key))
                         if edge is not None and edge[1] is not None}
            if consumer not in impacted and not providers & impacted:
                return {"status": "RESOLUTION_FAILED", "code": "LOCK_UNRELATED_EDGE_DELTA",
                        "path": consumer, "dependency": key[1]}
            edge_changes += 1
    return {"status": "RESOLUTION_PASSED", "code": "LOCK_IMPACT_CLOSURE_MATCH",
            "changedPackageCount": len(delta), "changedEdgeCount": edge_changes,
            "impactedInstanceCount": len(impacted)}
