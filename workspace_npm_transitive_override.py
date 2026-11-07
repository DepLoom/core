"""Find narrowly scoped npm override candidates from lock and audit evidence."""
from __future__ import annotations

import re

from semantic_version import NpmSpec, Version

from project_runtime import normalize_npm_range
from workspace_npm_lock_delta import _edges

_NAME = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+")
_INSTALL_SECTIONS = {"dependencies", "optionalDependencies"}


def _package_name(path):
    return path.rsplit("/node_modules/", 1)[-1].removeprefix("node_modules/")


def _stable(value):
    if not isinstance(value, str):
        return None
    try:
        version = Version(value)
    except ValueError:
        return None
    return version if not version.prerelease and not version.build else None


def _touches_existing_override(overrides, names):
    for selector, value in overrides.items():
        package = selector.split('@', 1)[0] if not selector.startswith('@') else '@' + selector[1:].split('@', 1)[0]
        if package in names or isinstance(value, dict) and _touches_existing_override(value, names):
            return True
    return False


def propose_npm_transitive_overrides(packages, overrides, dependency, affected_paths, advisory_ranges, versions=(),
                                     *, only_version=None, selected_consumer_paths=None):
    """Return review-only options, using caller-supplied advisory ranges.

    An audit range is an exclusion, not proof that the replacement has no
    other advisories. npm resolution and affected runtime still need checks.
    """
    evidence = {"authority": "PLANNING_ONLY", "verification": "NOT_VERIFIED",
                "security": "SUPPLIED_ADVISORY_RANGES_ONLY", "executionReady": False}

    def result(code, options=()):
        return {**evidence, "code": code, "options": list(options)}

    if (not isinstance(dependency, str) or not _NAME.fullmatch(dependency)
            or not 1 <= len(affected_paths) <= 64 or not 1 <= len(advisory_ranges) <= 32
            or len(versions) > 256 or len(packages) > 20000):
        return result("OVERRIDE_INPUT_UNSUPPORTED")
    try:
        exclusions = [NpmSpec(normalize_npm_range(value)) for value in advisory_ranges]
    except ValueError:
        return result("OVERRIDE_ADVISORY_RANGE_UNSUPPORTED")

    affected = set(affected_paths)
    affected_versions = {}
    for path in affected:
        entry = packages.get(path, {})
        version = _stable(entry.get("version"))
        if (_package_name(path) != dependency or entry.get("name", dependency) != dependency
                or entry.get("link") or version is None
                or not any(spec.match(version) for spec in exclusions)):
            return result("OVERRIDE_AUDIT_PATH_MISMATCH")
        affected_versions[path] = version
    consumers = {}
    for path, entry in packages.items():
        if entry.get("link") or not any(dependency in entry.get(section, {}) for section in
                                       (*_INSTALL_SECTIONS, "devDependencies", "peerDependencies")):
            continue
        for (section, name), (spec, provider) in _edges(packages, path).items():
            if name == dependency:
                consumers.setdefault(path, []).append((section, spec, provider))

    bindings = {path: {provider[0] for _, _, provider in edges if provider and provider[0] in affected}
                for path, edges in consumers.items()}
    impacted = {path for path, providers in bindings.items() if providers}
    if set().union(*bindings.values()) != affected:
        return result("OVERRIDE_CONSUMER_UNRESOLVED")
    remaining = 0
    if selected_consumer_paths is not None:
        if (not isinstance(selected_consumer_paths, (tuple, list)) or not 1 <= len(selected_consumer_paths) <= 64
                or any(not isinstance(path, str) or path not in impacted for path in selected_consumer_paths)
                or len(set(selected_consumer_paths)) != len(selected_consumer_paths)):
            return result("OVERRIDE_CONSUMER_SELECTION_MISMATCH")
        selected = set(selected_consumer_paths)
        remaining = len(impacted - selected)
        impacted = selected
    latest_affected = max(affected_versions[provider] for path in impacted for provider in bindings[path])
    selectors = {}
    covered = set()
    ranges = []
    for path in sorted(impacted):
        parent = _package_name(path)
        entry = packages[path]
        version = _stable(entry.get("version"))
        if (not path.startswith("node_modules/") and "/node_modules/" not in path
                or not _NAME.fullmatch(parent) or entry.get("name", parent) != parent
                or parent == dependency or version is None):
            return result("OVERRIDE_PARENT_UNSUPPORTED")
        selector = f"{parent}@{version}"
        if _touches_existing_override(overrides, {parent, dependency}):
            return result("OVERRIDE_EXISTING_RULE_REQUIRES_REVIEW")
        for section, spec, provider in consumers[path]:
            if section not in _INSTALL_SECTIONS or not provider or provider[0] not in affected:
                return result("OVERRIDE_EDGE_SCOPE_UNSUPPORTED")
            try:
                ranges.append(NpmSpec(normalize_npm_range(spec)))
            except ValueError:
                return result("OVERRIDE_DECLARED_RANGE_UNSUPPORTED")
            covered.add(provider[0])
        selectors[selector] = (parent, str(version))
    for path in consumers.keys() - impacted:
        if (_package_name(path), packages[path].get("version")) in selectors.values():
            return result("OVERRIDE_SELECTOR_WOULD_TOUCH_OTHER_COPY")

    # npm's nested override selector also applies below its named parent.
    # Inspect logical descendants, including hoisted providers.
    pending = list(impacted)
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        for (section, name), (_, provider) in _edges(packages, path).items():
            if name == dependency and path not in impacted:
                return result("OVERRIDE_SELECTOR_WOULD_TOUCH_DESCENDANT")
            if section not in _INSTALL_SECTIONS or not provider:
                continue
            if packages[provider[0]].get("link"):
                return result("OVERRIDE_LINKED_DESCENDANT_UNSUPPORTED")
            pending.append(provider[0])

    locked = {_stable(entry.get("version")) for path, entry in packages.items()
              if _package_name(path) == dependency and not entry.get("link")
              and entry.get("name", dependency) == dependency}
    candidates = (locked | {_stable(value) for value in versions}) - {None}
    options = []
    for version in sorted(candidates):
        if (only_version is not None and str(version) != only_version) or any(spec.match(version) for spec in exclusions):
            continue
        within = all(spec.match(version) for spec in ranges)
        options.append({"version": str(version), "alreadyLocked": version in locked,
                        "versionDirection": "DOWNGRADE" if version < latest_affected else "UPGRADE",
                        "declaredRange": "MATCH" if within else "OUTSIDE_REQUIRES_RUNTIME_REVIEW",
                        "overrides": {selector: {dependency: str(version)} for selector in selectors},
                        "consumerPaths": sorted(impacted), "affectedPaths": sorted(covered),
                        "remainingAffectedConsumerCount": remaining,
                        "parentSelectorEffect": "EFFECTIVE_INBOUND_RANGE_MAY_BE_PINNED"})
    options.sort(key=lambda row: (row["versionDirection"] == "DOWNGRADE", row["declaredRange"] != "MATCH"))
    return result("OVERRIDE_REVIEW_OPTIONS" if options else "OVERRIDE_NO_KNOWN_CANDIDATE", options[:5])


def verify_npm_transitive_override(baseline, candidate, before_overrides, after_overrides,
                                  dependency, affected_paths, advisory_ranges, version, *, selected_consumer_paths=None):
    """Check observed lock bindings for a single scoped override option."""
    evidence = {"authority": "LOCKFILE_ONLY", "verification": "NOT_VERIFIED",
                "installation": "NOT_RUN", "runtime": "NOT_RUN", "executionReady": False}

    def result(code, **details):
        return {**evidence, "code": code, **details}

    proposal = propose_npm_transitive_overrides(
        baseline, before_overrides, dependency, affected_paths, advisory_ranges, [version],
        only_version=version, selected_consumer_paths=selected_consumer_paths,
    )
    option = next((row for row in proposal["options"] if row["version"] == version), None)
    if option is None or len(candidate) > 20000:
        return result("OVERRIDE_VERIFICATION_INPUT_UNSUPPORTED", proposalCode=proposal["code"])
    if after_overrides != {**before_overrides, **option["overrides"]}:
        return result("OVERRIDE_MANIFEST_RULE_MISMATCH")

    targets = set(option["consumerPaths"])
    before_edges = {}
    after_edges = {}
    selected_providers = []

    def binding(packages, provider):
        if provider is None:
            return None
        path, version = provider
        entry = packages[path]
        return (path, version, entry.get("resolved"), entry.get("integrity"), entry.get("link"), entry.get("name"))

    def child_edges(edges):
        return {section: edge for (section, name), edge in edges.items() if name == dependency}

    for consumer in sorted(baseline.keys() | candidate.keys()):
        before_edges[consumer] = _edges(baseline, consumer)
        after_edges[consumer] = _edges(candidate, consumer)
        left = child_edges(before_edges[consumer])
        right = child_edges(after_edges[consumer])
        if consumer not in targets:
            if ({section: (spec, binding(baseline, provider)) for section, (spec, provider) in left.items()}
                    != {section: (spec, binding(candidate, provider)) for section, (spec, provider) in right.items()}):
                return result("OVERRIDE_UNRELATED_BINDING_CHANGED", consumerPath=consumer)
            continue
        parent_before, parent_after = baseline[consumer], candidate.get(consumer, {})
        identity = ("version", "name", "resolved", "integrity", "link")
        if any(parent_before.get(key) != parent_after.get(key) for key in identity) or left.keys() != right.keys():
            return result("OVERRIDE_CONSUMER_CHANGED", consumerPath=consumer)
        for section, (spec, provider) in right.items():
            if (left[section][0] != spec or provider is None or provider[1] != version
                    or candidate[provider[0]].get("link")
                    or candidate[provider[0]].get("name", dependency) != dependency):
                return result("OVERRIDE_TARGET_BINDING_MISMATCH", consumerPath=consumer, section=section,
                              expectedVersion=version, actualVersion=provider[1] if provider else None)
            selected_providers.append((left[section][1][0], provider[0]))

    def leaf(packages, edges, path):
        entry = packages[path]
        return not edges[path] and not any(entry.get(key) for key in (
            "bundleDependencies", "bundledDependencies", "inBundle", "hasShrinkwrap",
        ))

    other_bindings = "NOT_ASSESSED_NON_LEAF"
    if all(leaf(baseline, before_edges, old) and leaf(candidate, after_edges, new)
           for old, new in selected_providers):
        for consumer in before_edges:
            left, right = before_edges[consumer], after_edges[consumer]
            for key in sorted(left.keys() | right.keys()):
                if consumer in targets and key[1] == dependency:
                    continue
                old_spec, old_provider = left.get(key, (None, None))
                new_spec, new_provider = right.get(key, (None, None))
                if ((key in left) != (key in right)
                        or (old_spec, binding(baseline, old_provider)) != (new_spec, binding(candidate, new_provider))):
                    return result("OVERRIDE_OTHER_LOCK_BINDING_CHANGED", consumerPath=consumer,
                                  section=key[0], dependency=key[1])
        other_bindings = "UNCHANGED_DECLARED_LOCK_BINDINGS"

    return result("OVERRIDE_LOCK_BINDINGS_MATCH", otherLockBindings=other_bindings, version=version, consumerPaths=sorted(targets),
                  declaredRange=option["declaredRange"],
                  remainingAffectedConsumerCount=option["remainingAffectedConsumerCount"],
                  parentSelectorEffect=option["parentSelectorEffect"])
