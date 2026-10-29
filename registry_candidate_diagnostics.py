"""Conservative, bounded registry candidate rejection evidence (Core issue #3).

The existing LiveDataClient.registry_artifact_url_allowed remains the only
source of an admission verdict. This module CLASSIFIES already-rejected URLs;
it never normalizes a foreign URL into an allowed one, fetches from the network,
or claims that a structurally accepted package can be installed.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit, unquote
import re


MAX_SAMPLES = 4
REJECTION_CODES = frozenset({
    "MISSING_DIST_TARBALL", "FOREIGN_TARBALL_ORIGIN", "BAD_REGISTRY_PATH",
    "HTTP_ARTIFACT_UNAVAILABLE",
})


def _identity(url: str) -> dict[str, Any]:
    """Return a bounded URL identity, never userinfo, query or fragment."""
    try:
        parts = urlsplit(str(url or ""))
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port if parts.port is not None else (
            443 if scheme == "https" else 80 if scheme == "http" else None
        )
    except ValueError:
        return {"origin": None, "pathPrefix": None}
    if scheme not in {"http", "https"} or not host:
        return {"origin": None, "pathPrefix": None}
    # Hostnames from urlsplit omit userinfo. IPv6 must be bracketed in origins.
    printable_host = f"[{host}]" if ":" in host else host
    origin = f"{scheme}://{printable_host}"
    if port not in (443 if scheme == "https" else 80, None):
        origin += f":{port}"
    # Avoid accidental credentials/tokens in URI path segments. Keep path
    # segment structure useful for diagnosing a mismatched Nexus prefix.
    segments = parts.path.rstrip("/").split("/")
    safe = []
    for segment in segments:
        if not segment:
            continue
        # A registry path is untrusted metadata; never forward encoded userinfo,
        # query-like credentials, controls, or arbitrary secrets to artifacts.
        # Keep only predictable structural prefix components.
        decoded = unquote(segment)
        suspicious = (
            not re.fullmatch(r"[A-Za-z0-9._~@+-]{1,48}", decoded)
            or bool(re.search(r"(?i)(token|apikey|api-key|secret|password|bearer|authorization|credential|access[-_]?key)", decoded))
            or bool(re.fullmatch(r"[0-9a-fA-F]{24,}", decoded))
        )
        safe.append("[redacted]" if suspicious else decoded)
        if len(safe) >= 12:
            break
    prefix = "/" + "/".join(safe) if safe else "/"
    if len(prefix) > 160:
        prefix = prefix[:155] + "[...]"
    return {"origin": origin, "pathPrefix": prefix}


def _reason_for_rejected_url(registry: str, tarball: str) -> str:
    """Classify only *after* the Core origin/path guard rejects a URL."""
    if not tarball:
        return "MISSING_DIST_TARBALL"
    registry_identity = _identity(registry)
    target_identity = _identity(tarball)
    if target_identity["origin"] is None:
        return "BAD_REGISTRY_PATH"
    if target_identity["origin"] != registry_identity["origin"]:
        return "FOREIGN_TARBALL_ORIGIN"
    return "BAD_REGISTRY_PATH"


def summarize_structural_candidates(
    registry: str,
    metadata: Mapping[str, Any],
    versions: Iterable[str],
    is_allowed: Callable[[str], bool],
    *,
    current: str = "",
) -> dict[str, Any]:
    """Explain the exact version list examined by the existing planning loop.

    Calling is_allowed delegates every admission decision to the existing
    guarded Core predicate. The returned dictionary contains no tarball URL,
    authorization header or credentials.
    """
    reasons: Counter[str] = Counter()
    samples: list[dict[str, str]] = []
    foreign_origins: list[str] = []
    seen: set[str] = set()
    totals = {"examined": 0, "accepted": 0, "rejected": 0,
              "upgradeCandidates": 0, "acceptedUpgradeCandidates": 0,
              "rejectedUpgradeCandidates": 0}
    published = metadata.get("versions") or {}
    if not isinstance(published, dict):
        published = {}
    for raw_version in versions:
        version = str(raw_version)
        totals["examined"] += 1
        if version != str(current):
            totals["upgradeCandidates"] += 1
        details = published.get(version)
        dist = details.get("dist") if isinstance(details, dict) else None
        tarball = str(dist.get("tarball") or "").strip() if isinstance(dist, dict) else ""
        if tarball and is_allowed(tarball):
            totals["accepted"] += 1
            if version != str(current):
                totals["acceptedUpgradeCandidates"] += 1
            continue
        code = _reason_for_rejected_url(registry, tarball)
        reasons[code] += 1
        totals["rejected"] += 1
        if version != str(current):
            totals["rejectedUpgradeCandidates"] += 1
        if len(samples) < MAX_SAMPLES:
            samples.append({"version": version[:64], "code": code})
        if code == "FOREIGN_TARBALL_ORIGIN":
            origin = _identity(tarball).get("origin")
            if origin and origin not in seen:
                seen.add(origin)
                if len(foreign_origins) < MAX_SAMPLES:
                    foreign_origins.append(origin)
    all_upgrades_rejected = bool(
        totals["upgradeCandidates"] > 0
        and totals["acceptedUpgradeCandidates"] == 0
        and totals["rejectedUpgradeCandidates"] == totals["upgradeCandidates"]
    )
    return {
        "schemaVersion": 1,
        "authority": "STRUCTURAL_REGISTRY_EVIDENCE_ONLY",
        "configuredRegistry": _identity(registry),
        "metadataRequestBase": _identity(registry),
        "metadataRequestBaseAuthority": "CONFIGURATION_NOT_HTTP_TRACE",
        **totals,
        "rejectionCounts": {k: reasons[k] for k in sorted(reasons)},
        "rejectionSamples": samples,
        "rejectedArtifactOrigins": foreign_origins,
        "allUpgradeCandidatesRejected": all_upgrades_rejected,
        "physicalProbe": {"observed": 0, "failureCounts": {}, "unprobed": True},
    }


def with_observed_physical_probes(
    structural: Mapping[str, Any],
    observed: Mapping[str, Mapping[str, Any]],
    *,
    current: str = "",
) -> dict[str, Any]:
    """Add only already-performed Core probes, never trigger extra network IO."""
    report = dict(structural)
    counts: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    for version, evidence in observed.items():
        if str(version) == str(current) or not isinstance(evidence, Mapping):
            continue
        state = str(evidence.get("status") or "unknown")
        counts[state] += 1
        if state in {"missing-artifact", "empty-artifact"}:
            failures["HTTP_ARTIFACT_UNAVAILABLE"] += 1
        elif state == "foreign-registry-redirect":
            failures["FOREIGN_TARBALL_ORIGIN"] += 1
    # Planning-only is evidence of a known URL, NOT physical availability.
    report["physicalProbe"] = {
        "observed": sum(counts.values()),
        "statusCounts": {k: counts[k] for k in sorted(counts)},
        "failureCounts": {k: failures[k] for k in sorted(failures)},
        "unprobed": not any(k not in {"planning-only", "current-installed"} for k in counts),
    }
    return report


def no_target_diagnostic_code(status: str, evidence: Mapping[str, Any]) -> str | None:
    """Never reclassify solver or status; explain a *confirmed* failure mode."""
    if status == "candidate-search-truncated":
        return "CANDIDATE_CAP"
    if status != "no-target":
        return None
    if evidence.get("allUpgradeCandidatesRejected") is True:
        return "NO_INSTALLABLE_ARTIFACT"
    if evidence.get("upgradeCandidates") == 0:
        return "NO_PUBLISHED_UPGRADE_CANDIDATE"
    return "UNRESOLVED_TARGET_CONSTRAINT_OR_POLICY"
