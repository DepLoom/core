"""Postconditions for a candidate npm workspace lock.

The result describes lockfile evidence. Installation and runtime checks are
separate and must observe the actual tree.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from semantic_version import NpmSpec, Version

from draft_npm_preflight import _npm_command
from verification_process_supervisor import run_supervised

from resolution_inventory import npm_lock_resolved_instance
from workspace_peer_model import Declaration
from workspace_glob import match_workspace_pattern
from workspace_npm_lock_delta import INSTALL_SECTIONS, check_workspace_lock_delta, peer_context


def check_workspace_lock(packages: dict, assignment: dict[Declaration, str]) -> dict:
    evidence = {"authority": "LOCKFILE_ONLY", "installation": "NOT_RUN", "runtime": "NOT_RUN",
                "learningAllowed": False}
    for (owner, section, name), expected in sorted(assignment.items()):
        instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
        if instance is None or instance[1] != expected:
            return {**evidence, "status": "RESOLUTION_FAILED", "code": "LOCK_ASSIGNMENT_MISMATCH",
                    "declaration": [owner, section, name], "expectedVersion": expected,
                    "actualVersion": instance[1] if instance else None}
    for consumer, entry in sorted(packages.items()):
        if not isinstance(entry, dict):
            return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_ENTRY"}
        if entry.get("link"):
            continue
        peers = entry.get("peerDependencies", {})
        peer_meta = entry.get("peerDependenciesMeta", {})
        if not isinstance(peers, dict) or not isinstance(peer_meta, dict):
            return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_PEER_METADATA"}
        # Registry package peers resolve next to the consumer or above it.
        # Workspace manifests resolve relative to the real workspace directory.
        context = peer_context(consumer)
        for name, spec in sorted(peers.items()):
            flags = peer_meta.get(name, {})
            if not isinstance(spec, str) or not isinstance(flags, dict):
                return {**evidence, "status": "UNKNOWN", "code": "INVALID_LOCK_PEER_METADATA"}
            provider = npm_lock_resolved_instance(packages, name, context)
            if provider is None and flags.get("optional") is True:
                continue
            try:
                valid = provider is not None and NpmSpec(spec).match(Version(provider[1]))
            except ValueError:
                return {**evidence, "status": "UNKNOWN", "code": "UNSUPPORTED_LOCK_PEER_RANGE",
                        "consumer": consumer, "peer": name}
            if not valid:
                return {**evidence, "status": "RESOLUTION_FAILED", "code": "LOCK_PEER_MISMATCH",
                        "consumer": consumer, "peer": name, "requiredRange": spec,
                        "providerPath": provider[0] if provider else None,
                        "providerVersion": provider[1] if provider else None}
    return {**evidence, "status": "RESOLUTION_PASSED", "code": "LOCK_ASSIGNMENT_AND_PEERS_MATCH"}

_SPEC = re.compile(r"[0-9A-Za-z.*+^~<>=| -]+")
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def run_workspace_npm_preflight(
    manifests: dict[str, bytes],
    baseline_lock: bytes,
    assignment: dict[Declaration, str],
    mutable: frozenset[Declaration],
    *,
    artifacts: Path,
    cache: Path,
    registry: str,
    timeout_seconds: int = 60,
    reauthor: Declaration | None = None,
) -> dict:
    """Check a hash-bound candidate with npm in an isolated, offline directory."""
    evidence = {"authority": "LOCKFILE_ONLY", "installation": "NOT_RUN", "runtime": "NOT_RUN",
                "learningAllowed": False, "lockMode": "PRESERVE_BASELINE"}
    if (not 1 <= timeout_seconds <= 60 or not 1 <= len(manifests) <= 256
            or "." not in manifests or not mutable <= assignment.keys()):
        return {**evidence, "status": "UNKNOWN", "code": "INVALID_WORKSPACE_PREFLIGHT_INPUT"}

    try:
        projects = {owner: json.loads(raw) for owner, raw in manifests.items()}
        lock = json.loads(baseline_lock)
        packages = lock["packages"]
        if lock["lockfileVersion"] != 3 or not isinstance(packages, dict):
            raise ValueError("Expected npm v3 lock")
        patterns = projects["."].get("workspaces")
        owners = projects.keys() - {"."}
        if (not isinstance(patterns, list) or not 1 <= len(patterns) <= 128
                or any(not isinstance(pattern, str) or not re.fullmatch(r"[A-Za-z0-9_./*-]+", pattern)
                       or "**" in pattern or any(part in {"", ".", "..", "node_modules", ".git"}
                                                for part in pattern.split("/"))
                       for pattern in patterns)
                or any(not any(match_workspace_pattern(owner, pattern) for owner in owners)
                       for pattern in patterns)
                or any(not any(match_workspace_pattern(owner, pattern) for pattern in patterns)
                       for owner in owners)):
            raise ValueError("Unproven workspace membership")
        lock_owners = {key for key in packages if key and "node_modules" not in key.split("/")}
        if lock_owners != owners:
            raise ValueError("Workspace membership differs from lock")
        for owner, project in projects.items():
            if (owner != "." and (not re.fullmatch(r"[A-Za-z0-9_./-]+", owner)
                    or PurePosixPath(owner).is_absolute()
                    or any(part in {"", ".", "..", "node_modules", ".git"} for part in owner.split("/")))):
                raise ValueError("Unsafe workspace owner")
            if not isinstance(project, dict) or "overrides" in project:
                raise ValueError("Unsupported manifest")
            record = packages["" if owner == "." else owner]
            if any(project.get(section, {}) != record.get(section, {})
                   for section in (*INSTALL_SECTIONS, "peerDependencies")):
                raise ValueError("Manifest and lock disagree")
            for section in (*INSTALL_SECTIONS, "peerDependencies"):
                for spec in project.get(section, {}).values():
                    if not isinstance(spec, str) or not _SPEC.fullmatch(spec):
                        raise ValueError("Unsupported dependency spec")
        for path, row in packages.items():
            if path and (not re.fullmatch(r"[A-Za-z0-9_./@+-]+", path)
                         or any(part in {"", ".", "..", ".git"} for part in path.split("/"))):
                raise ValueError("Unsafe lock entry")
            if not isinstance(row, dict):
                raise ValueError("Invalid lock entry")
            resolved = row.get("resolved")
            if row.get("link"):
                if resolved not in manifests or resolved == ".":
                    raise ValueError("Foreign workspace link")
            elif resolved is not None:
                url = urlsplit(resolved)
                if url.scheme != "https" or not url.hostname or url.username or url.password:
                    raise ValueError("Unsupported lock artifact")

        observed = {(owner, section, name) for owner, project in projects.items()
                    for section in INSTALL_SECTIONS for name in project.get(section, {})}
        if observed != assignment.keys():
            raise ValueError("Incomplete owner assignment")
        manifest_deltas = {}
        changed = set()
        for key, expected in assignment.items():
            owner, section, name = key
            instance = npm_lock_resolved_instance(packages, name, "" if owner == "." else owner)
            if instance is None:
                raise ValueError("Unproven baseline resolution")
            if expected != instance[1]:
                if key not in mutable or not _VERSION.fullmatch(expected) or packages[instance[0]].get("link"):
                    return {**evidence, "status": "RESOLUTION_FAILED", "code": "UNAUTHORIZED_DECLARATION_DELTA",
                            "declaration": list(key)}
                projects[owner][section][name] = expected
                lock_owner = "" if owner == "." else owner
                manifest_deltas.setdefault(lock_owner, {}).setdefault(section, {})[name] = expected
                changed.add(key)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {**evidence, "status": "UNKNOWN", "code": "INVALID_WORKSPACE_PREFLIGHT_INPUT"}

    try:
        artifacts.mkdir(parents=True, exist_ok=True)
        workspace = Path(tempfile.mkdtemp(prefix="workspace-npm-", dir=artifacts))
        candidate_manifests = {}
        for owner, project in projects.items():
            path = workspace / owner / "package.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = manifests[owner]
            if project != json.loads(raw):
                raw = (json.dumps(project, indent=2) + "\n").encode("utf-8")
            path.write_bytes(raw)
            candidate_manifests[path] = raw
        lock_path = workspace / "package-lock.json"
        lock_path.write_bytes(baseline_lock)
        node, npm_cli = _npm_command()
        user_config = workspace / "user.npmrc"
        global_config = workspace / "global.npmrc"
        for config in (user_config, global_config):
            config.touch(exist_ok=False)
        npm_env = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(("NPM_CONFIG_", "NODE_", "NPM_PACKAGE_", "NPM_LIFECYCLE_"))}
        identity = {
            "baselineLockSha256": hashlib.sha256(baseline_lock).hexdigest(),
            "sourceManifestSha256": {owner: hashlib.sha256(raw).hexdigest()
                                     for owner, raw in sorted(manifests.items())},
            "candidateManifestSha256": {
                path.parent.relative_to(workspace).as_posix(): hashlib.sha256(raw).hexdigest()
                for path, raw in candidate_manifests.items()
            },
            "assignment": [[*key, value] for key, value in sorted(assignment.items())],
            "mutable": [list(key) for key in sorted(mutable)],
            "reauthor": list(reauthor) if reauthor is not None else None,
            "registrySha256": hashlib.sha256(registry.encode()).hexdigest(),
        }
        for label, executable in (("nodeBinarySha256", node), ("npmEntrypointSha256", npm_cli)):
            with Path(executable).open("rb") as stream:
                identity[label] = hashlib.file_digest(stream, "sha256").hexdigest()
        argv = [node, npm_cli,
            "install", "--package-lock-only", "--package-lock=true", "--strict-peer-deps=true",
            "--engine-strict=true", "--ignore-scripts=true", "--force=false", "--legacy-peer-deps=false",
            "--install-strategy=hoisted", "--prefer-dedupe=false", "--no-audit", "--no-fund",
            "--global=false", "--workspaces=true", "--include-workspace-root=true",
            "--include=prod", "--include=dev", "--include=optional", "--include=peer",
            "--offline=true", "--prefer-offline=false", "--registry", registry, "--cache", str(cache),
            "--userconfig", str(user_config), "--globalconfig", str(global_config),
        ]
        # Record only deterministic policy flags. Registry, cache and config paths stay local.
        identity["npmPolicy"] = argv[2:argv.index("--registry")]
        identity_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        deadline = time.monotonic() + timeout_seconds
        attempts = []

        def resolve(label):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            proc = run_supervised(argv, workspace, timeout_seconds=remaining,
                                  progress_label=f"Workspace npm resolution: {label}", base_env=npm_env)
            output = proc.stdout or ""
            log = workspace / f"{label}.log"
            log.write_text(output, encoding="utf-8")
            attempts.append({"phase": label, "npmExitCode": proc.returncode,
                             "outputSha256": hashlib.sha256(log.read_bytes()).hexdigest()})
            match = re.search(r"npm (?:error|ERR!) code ([A-Z][A-Z0-9_]+)", output)
            return proc.returncode, match.group(1) if match else "NPM_RESOLUTION_ERROR"

        def check(exit_code, code):
            if exit_code:
                status = "RESOLUTION_FAILED" if code in {"ERESOLVE", "EBADENGINE"} else "UNKNOWN"
                return {"status": status, "code": code}
            return check_workspace_lock(json.loads(lock_path.read_bytes())["packages"], assignment)

        reauthored = None
        exit_code, code = resolve("npm-resolution")
        result = check(exit_code, code)
        if (reauthor is not None and reauthor in assignment and reauthor not in mutable
                and result["code"] == "LOCK_PEER_MISMATCH"):
            owner, section, name = reauthor
            resolved = json.loads(lock_path.read_bytes())["packages"]
            instance = npm_lock_resolved_instance(resolved, name, "" if owner == "." else owner)
            same_slot = [
                key for key in assignment if key[2] == name and
                npm_lock_resolved_instance(resolved, name, "" if key[0] == "." else key[0]) == instance
            ]
            if (instance is not None and result["consumer"] == instance[0]
                    and same_slot == [reauthor] and projects[owner][section][name] == assignment[reauthor]
                    and _VERSION.fullmatch(assignment[reauthor]) and not resolved[instance[0]].get("link")):
                reauthored = reauthor
                attempts[-1].update(status=result["status"], code=result["code"])
                path = workspace / owner / "package.json"
                before = path.read_bytes()
                intermediate = json.loads(before)
                del intermediate[section][name]
                try:
                    path.write_text(json.dumps(intermediate, indent=2) + "\n", encoding="utf-8")
                    exit_code, code = resolve("reauthor-remove")
                finally:
                    path.write_bytes(before)
                if exit_code:
                    result = check(exit_code, code)
                else:
                    exit_code, code = resolve("reauthor-restore")
                    result = check(exit_code, code)
        if any(path.read_bytes() != raw for path, raw in candidate_manifests.items()):
            result = {"status": "UNKNOWN", "code": "CANDIDATE_MANIFEST_CHANGED"}
        if result["status"] == "RESOLUTION_PASSED":
            delta = check_workspace_lock_delta(
                lock, json.loads(lock_path.read_bytes()), manifest_deltas, assignment, changed, reauthored)
            if delta["status"] != "RESOLUTION_PASSED":
                result.update(status=delta["status"], code=delta["code"])
            result["lockDelta"] = delta
        receipt = {**evidence, **result, "npmExitCode": exit_code, "attempts": attempts,
                   "baselineLockSha256": identity["baselineLockSha256"],
                   "candidateLockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                   "resolverIdentitySha256": identity_digest}
        with (workspace / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump({"identity": identity, "receipt": receipt}, stream, indent=2)
        return {**receipt, "workspace": str(workspace)}
    except subprocess.TimeoutExpired:
        return {**evidence, "status": "UNKNOWN", "code": "RESOLVER_TIMEOUT"}
    except (AttributeError, OSError, ValueError, KeyError, TypeError):
        return {**evidence, "status": "UNKNOWN", "code": "RESOLVER_EVIDENCE_UNAVAILABLE"}
