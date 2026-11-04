"""Collect exact workspace health facts using the owning registry client."""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
from typing import Iterable, Mapping

from workspace_health_policy import WorkspaceHealthFact


def collect_workspace_health_facts(
    client,
    packuments: Mapping[str, dict],
    versions: Mapping[str, Iterable[str]],
    *,
    lag_months: int,
    osv_allowed_names: frozenset[str],
) -> tuple[dict[tuple[str, str], WorkspaceHealthFact], dict]:
    """Deduplicate exact versions and preserve missing dates and advisories as unknown."""
    from dependency_live_roadmap_generator import (
        SEVERITY_LABELS, VulnerabilityEvidenceUnavailable,
        min_by_lag, severity_rank, version_date,
    )

    if type(lag_months) is not int or lag_months not in {3, 6, 9, 12}:
        raise ValueError("INVALID_WORKSPACE_LAG_MONTHS")
    facts = {}
    rows = []
    skipped_names = 0
    for name in sorted(versions):
        candidates = sorted(set(versions[name]))
        meta = packuments.get(name, {})
        latest = client.latest_installable_version(name, meta, include_prerelease=False)
        latest_date = version_date(meta, latest)
        findings = {}
        if name in osv_allowed_names:
            try:
                findings = client.query_osv_versions(name, candidates)
            except VulnerabilityEvidenceUnavailable:
                findings = {}
        else:
            skipped_names += 1
        for version in candidates:
            observed = version_date(meta, version)
            lag_ok = None
            if latest_date is not None and observed is not None:
                try:
                    lag_ok = min_by_lag(meta, [version], lag_months, latest_override=latest) == version
                except TypeError:  # mixed aware/naive timestamps do not establish order
                    pass
            advisories = findings.get(version)
            severities = None
            if isinstance(advisories, list) and all(isinstance(item, dict) for item in advisories):
                severities = frozenset(SEVERITY_LABELS.get(severity_rank(item), "U") for item in advisories)
            facts[name, version] = WorkspaceHealthFact(lag_ok, severities)
            manifest = meta.get("versions", {}).get(version, {})
            manifest = manifest if isinstance(manifest, dict) else {}
            rows.append([name, version, latest, observed.isoformat() if observed else None,
                         latest_date.isoformat() if latest_date else None, lag_ok,
                         sorted(severities) if severities is not None else None,
                         {key: manifest.get(key) for key in ("name", "version", "peerDependencies",
                                                              "peerDependenciesMeta", "engines", "dist")}])
    registry_digest = sha256(client.registry.encode("utf-8")).hexdigest()
    encoded = json.dumps([registry_digest, rows], separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")
    return facts, {
        "status": "COLLECTED",
        "source": "CORE_REGISTRY_AND_EXACT_OSV",
        "registryIdentitySha256": registry_digest,
        "lagWindowMonths": lag_months,
        "lagReference": ("LATEST_ALLOWED_REGISTRY_METADATA" if getattr(client, "draft", False) else
                         "LATEST_INSTALLABLE_IN_CONFIGURED_REGISTRY"),
        "exactVersionCount": len(facts),
        "unknownLagVersionCount": sum(fact.lag_ok is None for fact in facts.values()),
        "unknownSecurityVersionCount": sum(fact.severities is None for fact in facts.values()),
        "osvSkippedNameCount": skipped_names,
        "snapshotSha256": sha256(encoded).hexdigest(),
    }


def workspace_registry_health_versions(packages, declarations, admitted_versions, exact_targets):
    """Build the registry version inventory from all actual non-link declarations."""
    from resolution_inventory import npm_lock_resolved_instance

    result = defaultdict(set)
    for key in declarations:
        owner, _, name = key
        installed = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if installed is None:
            raise ValueError("WORKSPACE_HEALTH_LOCK_INSTANCE_UNAVAILABLE")
        slot, current = installed
        if packages[slot].get("link"):
            continue
        if key in exact_targets:
            result[name].add(exact_targets[key])
        else:
            result[name].update(admitted_versions.get(key, (current,)))
    return dict(result)
