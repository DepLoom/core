"""Exact-version evidence from an explicitly approved npm registry."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from semantic_version import Version

SOURCE = "REGISTRY_BULK_ADVISORY"
_ENDPOINT = "/-/npm/v1/security/advisories/bulk"
_MAX_BODY_BYTES = 2 * 1024 * 1024
_NAME = re.compile(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+")
_SEVERITIES = frozenset({"critical", "high", "moderate", "low"})


@dataclass(frozen=True)
class RegistryAdvisory:
    identifier: str
    severity: str
    vulnerable_range: str


@dataclass(frozen=True)
class RegistryAdvisoryEvidence:
    status: str
    reason: str
    advisories: tuple[RegistryAdvisory, ...] = ()
    response_sha256: str | None = None
    retrieved_at: str | None = None
    source: str = SOURCE


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def registry_advisory_source_matches(registry: str, approved_registry: str) -> bool:
    try:
        parsed = urlsplit(registry)
        return bool(
            registry.rstrip("/") == approved_registry.rstrip("/")
            and parsed.scheme == "https" and parsed.hostname
            and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
            and not any(c.isspace() or c in r"\%?#" for c in registry)
            and all(part not in {".", ".."} for part in parsed.path.split("/"))
            and (parsed.port is None or 0 < parsed.port < 65536)
        )
    except ValueError:
        return False


def valid_registry_advisory_name(name: str) -> bool:
    return (len(name) <= 214 and bool(_NAME.fullmatch(name))
            and not any(part in {".", ".."} for part in name.split("/")))


def query_registry_advisories(
    session,
    registry: str,
    approved_registry: str,
    pairs: list[tuple[str, str]],
    *,
    matches: Callable[[str, str], bool],
    timeout: tuple[float, float],
    trust_omitted_packages: bool = False,
    max_match_evaluations: int | None = None,
) -> dict[tuple[str, str], RegistryAdvisoryEvidence]:
    """Query one trusted registry. The host supplies approval and omission policy.

    `matches(range, version)` must implement npm semver and raise ValueError
    for unsupported ranges. Missing package keys are unknown unless the host
    has established that omission is the registry's negative response.
    """
    requested = tuple(dict.fromkeys(pairs))
    if not requested:
        return {}

    def unknown(reason):
        return {pair: RegistryAdvisoryEvidence("UNKNOWN", reason) for pair in requested}

    if not registry_advisory_source_matches(registry, approved_registry):
        return unknown("REGISTRY_NOT_APPROVED")

    payload: dict[str, list[str]] = {}
    try:
        for name, version in requested:
            if not valid_registry_advisory_name(name) or str(Version(version)) != version:
                raise ValueError("invalid exact package/version")
            payload.setdefault(name, []).append(version)
    except (TypeError, ValueError):
        return unknown("INVALID_EXACT_PAIR")

    try:
        with session.post(
            registry.rstrip("/") + _ENDPOINT, json=payload, timeout=timeout,
            allow_redirects=False, stream=True,
        ) as response:
            if response.status_code != 200:
                return unknown("REGISTRY_HTTP_ERROR")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if len(body) + len(chunk) > _MAX_BODY_BYTES:
                    return unknown("RESPONSE_TOO_LARGE")
                body.extend(chunk)
    except (OSError, ValueError):
        return unknown("REGISTRY_TRANSPORT_ERROR")

    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) - set(payload):
            raise ValueError("invalid registry advisory envelope")
    except (UnicodeError, ValueError):
        return unknown("INVALID_ADVISORY_RESPONSE")

    digest = hashlib.sha256(body).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    evidence = {}
    comparisons = {}
    for name, version in requested:
        records = data.get(name)
        if name not in data and not trust_omitted_packages:
            evidence[name, version] = RegistryAdvisoryEvidence(
                "UNKNOWN", "COVERAGE_UNCONFIRMED", response_sha256=digest, retrieved_at=timestamp
            )
            continue
        try:
            matched = []
            if name not in data:
                records = []
            if not isinstance(records, list):
                raise ValueError("invalid advisory list")
            if max_match_evaluations is not None and len(records) > max_match_evaluations:
                evidence[name, version] = RegistryAdvisoryEvidence(
                    "UNKNOWN", "MATCH_BUDGET_EXHAUSTED", response_sha256=digest, retrieved_at=timestamp
                )
                continue
            for record in records:
                if not isinstance(record, dict) or record.get("name", name) != name:
                    raise ValueError("invalid advisory package")
                identifier = record.get("id")
                severity = record.get("severity")
                spec = record.get("vulnerable_versions")
                if (type(identifier) not in (int, str) or not str(identifier).strip()
                        or not isinstance(severity, str) or severity not in _SEVERITIES
                        or not isinstance(spec, str) or not spec.strip()):
                    raise ValueError("invalid advisory fields")
                key = (spec, version)
                if key not in comparisons:
                    if max_match_evaluations is not None and len(comparisons) >= max_match_evaluations:
                        evidence[name, version] = RegistryAdvisoryEvidence(
                            "UNKNOWN", "MATCH_BUDGET_EXHAUSTED", response_sha256=digest, retrieved_at=timestamp
                        )
                        break
                    try:
                        comparisons[key] = matches(spec, version)
                    except ValueError:
                        comparisons[key] = None
                applies = comparisons[key]
                if type(applies) is not bool:
                    raise ValueError("unknown advisory range")
                if applies:
                    matched.append(RegistryAdvisory(str(identifier), severity, spec))
        except ValueError:
            evidence[name, version] = RegistryAdvisoryEvidence(
                "UNKNOWN", "INVALID_ADVISORY_OR_RANGE", response_sha256=digest, retrieved_at=timestamp
            )
        else:
            if (name, version) in evidence:
                continue
            evidence[name, version] = RegistryAdvisoryEvidence(
                "AFFECTED" if matched else "NO_REPORTED_ADVISORIES",
                "REGISTRY_EXACT_VERSION", tuple(dict.fromkeys(matched)), digest, timestamp,
            )
    return evidence
