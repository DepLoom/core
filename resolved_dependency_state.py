from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Mapping, Optional
from project_topology import ProjectTopologyError, resolve_project_topology

# BLOCK_Z_PROJECT_TOPOLOGY_V1

RESOLVED_STATE_SCHEMA = "resolved-state-v1"


class ResolvedDependencyStateError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ResolvedDependencyState:
    key: str
    resolver_input_key: str
    manager: str
    lockfile_path: str
    lockfile_hash: str
    observed_resolved_hash: str
    artifact_relative_path: str
    lockfile_bytes: bytes = dataclasses.field(repr=False, compare=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _git_root_or_project(project_dir: Path) -> Path:
    from git_identity import git_toplevel

    root = git_toplevel(project_dir)
    if root is not None:
        return root
    return Path(project_dir).resolve()


def _lockfile_names(manager: str) -> tuple[str, ...]:
    manager = str(manager).lower()
    if manager == "yarn":
        return ("yarn.lock",)
    if manager == "pnpm":
        return ("pnpm-lock.yaml",)
    if manager == "npm":
        return ("npm-shrinkwrap.json", "package-lock.json")
    raise ResolvedDependencyStateError(f"RESOLVED_STATE_MANAGER_UNSUPPORTED: {manager}")


def _find_lockfile(project_dir: Path, manager: str) -> tuple[Path, Path]:
    project_dir = project_dir.resolve()
    try:
        topology = resolve_project_topology(
            project_dir,
            allow_discovery=False,
            require_supported=True,
        )
    except ProjectTopologyError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_PROJECT_TOPOLOGY_UNAVAILABLE: {exc}"
        ) from exc
    if topology.profile.manager != str(manager).lower():
        raise ResolvedDependencyStateError(
            "RESOLVED_STATE_MANAGER_TOPOLOGY_MISMATCH: "
            f"requested={manager}; topology={topology.profile.manager}"
        )
    identity_root = topology.git_root or topology.source_root
    return identity_root.resolve(), topology.lockfile.resolve()


def _state_key(
    *,
    resolver_input_key: str,
    manager: str,
    lockfile_path: str,
    lockfile_hash: str,
    observed_resolved_hash: str,
) -> str:
    return _canonical_hash({
        "schema": RESOLVED_STATE_SCHEMA,
        "resolverInputKey": str(resolver_input_key),
        "manager": str(manager),
        "lockfilePath": str(lockfile_path),
        "lockfileHash": str(lockfile_hash),
        "observedResolvedHash": str(observed_resolved_hash),
    })


def capture_resolved_dependency_state(
    project_dir: Path,
    *,
    manager: str,
    resolver_input_key: str,
    observed_resolved_hash: str,
    proof_cache_dir: Optional[Path],
) -> ResolvedDependencyState:
    git_root, lockfile = _find_lockfile(project_dir, manager)
    try:
        lockfile_bytes = lockfile.read_bytes()
    except OSError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_UNREADABLE: {lockfile}: {exc}"
        ) from exc
    lockfile_hash = _sha256_bytes(lockfile_bytes)
    try:
        lockfile_path = lockfile.relative_to(git_root).as_posix()
    except ValueError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_OUTSIDE_GIT_ROOT: {lockfile}"
        ) from exc

    key = _state_key(
        resolver_input_key=resolver_input_key,
        manager=manager,
        lockfile_path=lockfile_path,
        lockfile_hash=lockfile_hash,
        observed_resolved_hash=observed_resolved_hash,
    )
    artifact_relative_path = ""
    if proof_cache_dir is not None:
        root = proof_cache_dir.resolve()
        artifact = root / "resolved-state" / key / "lockfile.bin"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        if artifact.exists():
            existing = artifact.read_bytes()
            if _sha256_bytes(existing) != lockfile_hash:
                raise ResolvedDependencyStateError(
                    f"RESOLVED_STATE_ARTIFACT_COLLISION: {artifact}"
                )
        else:
            temporary = artifact.with_name(
                f"{artifact.name}.tmp-{os.getpid()}-{threading_get_ident()}"
            )
            temporary.write_bytes(lockfile_bytes)
            os.replace(temporary, artifact)
        artifact_relative_path = artifact.relative_to(root).as_posix()

    return ResolvedDependencyState(
        key=key,
        resolver_input_key=str(resolver_input_key),
        manager=str(manager),
        lockfile_path=lockfile_path,
        lockfile_hash=lockfile_hash,
        observed_resolved_hash=str(observed_resolved_hash),
        artifact_relative_path=artifact_relative_path,
        lockfile_bytes=lockfile_bytes,
    )


def threading_get_ident() -> int:
    # Kept local to avoid importing threading on the hot path unless persistence is used.
    import threading
    return threading.get_ident()


# Restore of a SHARED lockfile needs mutual exclusion, not just identity.
# The resolved-state key binds *content identity*: it proves exactly which
# bytes belong to a state, but it cannot by itself stop two verification
# attempts from concurrently restoring the same lockfile pathname (for example
# one root lockfile shared by several monorepo packages). os.replace already
# prevents a torn byte stream. The hash assertion detects observed drift, but
# does not grant cross-process exclusion or lock the following install. Actual
# verifier installs run in isolated clones, each with its own root lockfile.
# The per-path lock below makes
# write+verify one atomic critical section per pathname within this process, so
# concurrent restores of the same shared lockfile are serialized instead of
# interleaving their critical sections.
_RESTORE_TARGET_LOCKS: dict[str, threading.Lock] = {}
_RESTORE_TARGET_LOCKS_GUARD = threading.Lock()


def _restore_target_lock(target: Path) -> threading.Lock:
    key = os.path.normcase(str(Path(target).resolve()))
    with _RESTORE_TARGET_LOCKS_GUARD:
        lock = _RESTORE_TARGET_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _RESTORE_TARGET_LOCKS[key] = lock
        return lock


def resolved_state_metadata(state: ResolvedDependencyState) -> dict[str, str]:
    return {
        "resolvedStateKey": state.key,
        "resolvedStateResolverInputKey": state.resolver_input_key,
        "resolvedPackageManager": state.manager,
        "resolvedLockfilePath": state.lockfile_path,
        "resolvedLockfileHash": state.lockfile_hash,
        "resolvedStateArtifact": state.artifact_relative_path,
        "resolvedStateObservedHash": state.observed_resolved_hash,
    }


def load_resolved_dependency_state(
    metadata: Mapping[str, object],
    *,
    proof_cache_dir: Optional[Path],
) -> Optional[ResolvedDependencyState]:
    try:
        key = str(metadata.get("resolvedStateKey") or "")
        resolver_input_key = str(metadata.get("resolvedStateResolverInputKey") or "")
        manager = str(metadata.get("resolvedPackageManager") or "")
        lockfile_path = str(metadata.get("resolvedLockfilePath") or "")
        lockfile_hash = str(metadata.get("resolvedLockfileHash") or "")
        artifact_relative_path = str(metadata.get("resolvedStateArtifact") or "")
        observed_hash = str(metadata.get("resolvedStateObservedHash") or "")
        if not (
            len(key) == 64
            and len(lockfile_hash) == 64
            and len(observed_hash) == 64
            and resolver_input_key
            and manager
            and lockfile_path
            and artifact_relative_path
            and proof_cache_dir is not None
        ):
            return None

        root = proof_cache_dir.resolve()
        artifact = (root / Path(artifact_relative_path)).resolve()
        try:
            artifact.relative_to(root)
        except ValueError:
            return None
        if not artifact.is_file():
            return None
        lockfile_bytes = artifact.read_bytes()
        if _sha256_bytes(lockfile_bytes) != lockfile_hash:
            return None
        expected = _state_key(
            resolver_input_key=resolver_input_key,
            manager=manager,
            lockfile_path=lockfile_path,
            lockfile_hash=lockfile_hash,
            observed_resolved_hash=observed_hash,
        )
        if expected != key:
            return None
        return ResolvedDependencyState(
            key=key,
            resolver_input_key=resolver_input_key,
            manager=manager,
            lockfile_path=lockfile_path,
            lockfile_hash=lockfile_hash,
            observed_resolved_hash=observed_hash,
            artifact_relative_path=artifact_relative_path,
            lockfile_bytes=lockfile_bytes,
        )
    except (OSError, TypeError, ValueError):
        return None


def resolved_lockfile_path(project_dir: Path, state: ResolvedDependencyState) -> Path:
    git_root = _git_root_or_project(project_dir)
    target = (git_root / Path(state.lockfile_path)).resolve()
    try:
        target.relative_to(git_root)
    except ValueError as exc:
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_PATH_ESCAPE: {state.lockfile_path}"
        ) from exc
    return target


def restore_resolved_dependency_state(
    project_dir: Path, state: ResolvedDependencyState
) -> Path:
    target = resolved_lockfile_path(project_dir, state)
    with _restore_target_lock(target):
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f"{target.name}.deploom-resolved-{os.getpid()}.tmp")
        temporary.write_bytes(state.lockfile_bytes)
        os.replace(temporary, target)
        assert_resolved_dependency_state(project_dir, state)
    return target


def assert_resolved_dependency_state(
    project_dir: Path, state: ResolvedDependencyState
) -> None:
    target = resolved_lockfile_path(project_dir, state)
    if not target.is_file():
        raise ResolvedDependencyStateError(
            f"RESOLVED_STATE_LOCKFILE_DISAPPEARED: {state.lockfile_path}"
        )
    current_hash = _sha256_bytes(target.read_bytes())
    if current_hash != state.lockfile_hash:
        raise ResolvedDependencyStateError(
            "RESOLVED_STATE_LOCKFILE_DRIFT: "
            f"expected={state.lockfile_hash} current={current_hash} path={state.lockfile_path}"
        )


class MaterializedDependencyObligationError(RuntimeError):
    """Unknown installed evidence is never solver incompatibility or a nogood."""


def _obligation_json(raw, limit=8*1024*1024):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        if not isinstance(raw, bytes) or len(raw) > limit:
            raise ValueError('size/type')
        result = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if not isinstance(result, dict):
            raise ValueError('object required')
        return result
    except (UnicodeError, ValueError) as exc:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_JSON_UNPROVEN') from exc


def _ordinary_npm_obligation_mode(record):
    for key in ('link', 'inBundle'):
        if key in record and (type(record[key]) is not bool or record[key]):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLE_OR_LINK_UNSUPPORTED')
    for key in ('bundleDependencies', 'bundledDependencies'):
        if key in record and not (record[key] is False or type(record[key]) is list and not record[key]):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_BUNDLED_UNSUPPORTED')


def _npm_obligation_name(location, record):
    import re
    segment = r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*'
    if (not isinstance(location, str)
            or re.fullmatch(r'node_modules/'+segment+r'(?:/node_modules/'+segment+r')*', location) is None):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PATH_UNPROVEN')
    installed_name = location.rsplit('/node_modules/', 1)[-1].removeprefix('node_modules/')
    canonical_name = record.get('name', installed_name)
    if (not isinstance(canonical_name, str) or re.fullmatch(segment, canonical_name) is None
            or record.get('link') or not isinstance(record.get('version'), str)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_IDENTITY_UNPROVEN')
    from semantic_version import Version
    try:
        Version(record['version'])
    except ValueError as exc:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_VERSION_UNPROVEN') from exc
    return installed_name, canonical_name


def compile_npm_dependency_obligations(baseline_lock_bytes, candidate_lock_bytes, *,
        exact_targets, changed_instances, immutable_packages=(), excluded_packages=(),
        delta_digest, scope_digest, optional_absence_rules=()):
    """Compile expected npm-v2 obligations BEFORE observing installed output.

    Exact host delta/scope authorization remains with its existing owner. This
    compiler independently binds that delta to both lock graphs. It does not
    infer authorization, tarball authenticity or arbitrary runtime behavior.
    """
    import re
    before, after = (_obligation_json(raw) for raw in (baseline_lock_bytes, candidate_lock_bytes))
    if any(type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] != 2
            for lock in (before, after)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_UNSUPPORTED')
    if optional_absence_rules:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_OMISSION_RULE_UNSUPPORTED')
    if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (delta_digest, scope_digest)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_AUTHORIZATION_UNPROVEN')
    graphs = []
    for lock in (before, after):
        graph = lock.get('packages')
        if (not isinstance(graph, dict) or '' not in graph or not isinstance(graph[''], dict)
                or len(graph) > 10001 or any(not isinstance(row, dict) for row in graph.values())
                or len({name.casefold() for name in graph}) != len(graph)):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_GRAPH_UNPROVEN')
        for location, row in graph.items():
            _ordinary_npm_obligation_mode(row)
            if location:
                _npm_obligation_name(location, row)
        graphs.append(graph)
    old, new = graphs
    changed = {name for name in set(old) | set(new) if name and old.get(name) != new.get(name)}
    if (not isinstance(changed_instances, (list, tuple))
            or any(not isinstance(name, str) for name in changed_instances)
            or len(set(changed_instances)) != len(changed_instances) or set(changed_instances) != changed):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DELTA_MISMATCH')
    protected = set(immutable_packages) | set(excluded_packages)
    for location in changed:
        for graph in (old, new):
            if location in graph and protected.intersection(_npm_obligation_name(location, graph[location])):
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PROTECTED_DELTA')
    sections = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')
    root_before = {key: old[''].get(key, {}) for key in sections}
    root_after = {key: new[''].get(key, {}) for key in sections}
    expected = json.loads(json.dumps(root_before))
    for name, version in exact_targets.items():
        found = [key for key in sections if isinstance(expected[key], dict) and name in expected[key]]
        if len(found) != 1:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
        expected[found[0]][name] = version
    if expected != root_after:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_SCOPE_MISMATCH')
    instances = []
    for location in sorted(set(new) - {''}):
        row = new[location]; alias, name = _npm_obligation_name(location, row)
        instances.append({'path': location, 'installName': alias, 'name': name, 'version': row['version'],
            'lockRecordDigest': _canonical_hash(row), 'held': location in old and location not in changed,
            'metadata': {key: row.get(key, {}) for key in
                ('dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta')}})
    plan = {'schemaVersion': 1, 'kind': 'APPROVED_NPM_V2_INSTANCE_OBLIGATIONS',
        'baselineLockSha256': _sha256_bytes(baseline_lock_bytes),
        'approvedLockSha256': _sha256_bytes(candidate_lock_bytes),
        'approvedDeltaDigest': delta_digest, 'allowedChangeScopeDigest': scope_digest,
        'rootDeclarations': root_after, 'instances': instances, 'changedInstanceCount': len(changed),
        'optionalAbsenceRules': []}
    return {**plan, 'obligationPlanDigest': _canonical_hash(plan)}


def observe_npm_dependency_obligations(project_dir, plan, *, source_origin_digest, resolved_state_key, deadline=None):
    """Observe actual physical instance manifests and supported Node edge paths.

    Boundary observation, not continuous mutation or package-payload attestation.
    Missing optional instances remain UNKNOWN until explicit omission semantics
    are supported; they never disappear from the expected denominator.
    """
    import re
    from semantic_version import NpmSpec, Version
    import time
    def budget():
        if deadline is not None and time.monotonic() >= deadline:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DEADLINE_EXCEEDED')
    budget()
    project = Path(project_dir).resolve()
    if (not isinstance(plan, dict) or type(plan.get('schemaVersion')) is not int or plan['schemaVersion'] != 1
            or plan.get('obligationPlanDigest') != _canonical_hash({k: v for k, v in plan.items() if k != 'obligationPlanDigest'})):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PLAN_UNPROVEN')
    if any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (source_origin_digest, resolved_state_key)):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ORIGIN_UNPROVEN')
    lock = project / 'package-lock.json'
    if not lock.is_file() or _sha256_bytes(lock.read_bytes()) != plan['approvedLockSha256']:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LOCK_DRIFT')
    manifest = _obligation_json((project / 'package.json').read_bytes(), 1024*1024)
    _ordinary_npm_obligation_mode(manifest)
    if {key: manifest.get(key, {}) for key in plan['rootDeclarations']} != plan['rootDeclarations']:
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_DRIFT')
    expected = {row['path']: row for row in plan['instances']}
    actual = {}; folded = set(); manifest_bytes_read = 0
    def no_link(path):
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_REPARSE_UNPROVEN')
    def scan_modules(directory, prefix='', depth=0):
        nonlocal manifest_bytes_read
        budget()
        if depth > 64:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_DEPTH_LIMIT')
        if not directory.exists():
            return
        no_link(directory)
        for entry in sorted(directory.iterdir(), key=lambda p: p.name):
            if entry.name in {'.bin', '.package-lock.json'}:
                continue
            no_link(entry)
            if entry.name.startswith('@'):
                if not entry.is_dir():
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LAYOUT_UNPROVEN')
                paths = sorted(entry.iterdir(), key=lambda p: p.name)
            else:
                paths = [entry]
            for package in paths:
                budget()
                no_link(package)
                relative = package.relative_to(project).as_posix()
                if relative.casefold() in folded or not package.is_dir() or len(actual) >= 10000:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_LAYOUT_UNPROVEN')
                folded.add(relative.casefold())
                package_file = package / 'package.json'; no_link(package_file)
                if not package_file.is_file():
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_PACKAGE_MISSING')
                if package_file.stat().st_size > 1024*1024:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_SIZE_LIMIT')
                raw = package_file.read_bytes(); manifest_bytes_read += len(raw)
                if manifest_bytes_read > 64*1024*1024:
                    raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_MANIFEST_BUDGET_LIMIT')
                value = _obligation_json(raw, 1024*1024)
                _ordinary_npm_obligation_mode(value)
                actual[relative] = (value, _sha256_bytes(raw))
                scan_modules(package / 'node_modules', relative, depth+1)
    scan_modules(project / 'node_modules')
    if set(actual) != set(expected):
        raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_INSTANCE_SET_MISMATCH: '
            + json.dumps({'missing': sorted(set(expected)-set(actual))[:20], 'extra': sorted(set(actual)-set(expected))[:20]}))
    rows = []; edges = []
    def parent_instance(location):
        return location.rpartition('/node_modules/')[0] if '/node_modules/' in location else ''
    def resolve(location, name, peer=False):
        _npm_obligation_name('node_modules/'+name, {'version': '0.0.0'})
        base = parent_instance(location) if peer else location
        while True:
            candidate = (base+'/' if base else '')+'node_modules/'+name
            if candidate in actual:
                return candidate
            if not base:
                return None
            base = parent_instance(base)
    def edge(source, name, spec, peer=False):
        if not isinstance(spec, str):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_UNPROVEN')
        destination = resolve(source, name, peer)
        if destination is None:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_MISSING')
        wanted_name = None
        if spec.startswith('npm:'):
            match = re.fullmatch(r'npm:((?:@[^/]+/)?[^@]+)@(.+)', spec)
            if not match:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ALIAS_UNPROVEN')
            wanted_name, spec = match.groups()
        try:
            matched = NpmSpec(spec).match(Version(actual[destination][0]['version']))
        except (ValueError, KeyError) as exc:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_UNPROVEN') from exc
        expected_name = wanted_name if wanted_name is not None else name
        if actual[destination][0].get('name') != expected_name:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_IDENTITY_MISMATCH')
        if not matched:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_EDGE_MISMATCH')
        edges.append({'source': source, 'name': name, 'destination': destination, 'peer': peer, 'specifier': spec})
    for location, wanted in expected.items():
        value, digest = actual[location]
        if value.get('name') != wanted['name'] or value.get('version') != wanted['version']:
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_IDENTITY_MISMATCH: '+location)
        for key, metadata in wanted['metadata'].items():
            if not isinstance(metadata, dict) or value.get(key, {}) != metadata:
                raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_METADATA_UNPROVEN: '+location)
        for key in ('dependencies', 'optionalDependencies', 'peerDependencies'):
            for name, spec in wanted['metadata'][key].items():
                if key == 'dependencies' and name in wanted['metadata']['optionalDependencies']:
                    continue  # npm optionalDependencies override ordinary declarations.
                # Optional absence is intentionally not inferred from a missing
                # file or a successful npm exit. It remains a visible UNKNOWN.
                edge(location, name, spec, key == 'peerDependencies')
        rows.append({'path': location, 'name': wanted['name'], 'version': wanted['version'],
            'packageManifestSha256': digest, 'lockRecordDigest': wanted['lockRecordDigest'], 'held': wanted['held']})
    for key, declarations in plan['rootDeclarations'].items():
        if not isinstance(declarations, dict):
            raise MaterializedDependencyObligationError('DEPENDENCY_OBLIGATION_ROOT_UNPROVEN')
        for name, spec in declarations.items():
            if key == 'dependencies' and name in plan['rootDeclarations']['optionalDependencies']:
                continue
            edge('', name, spec)
    budget()
    return {'schemaVersion': 1, 'authority': 'NON_REUSABLE_CORE_OBSERVATION',
        'status': 'MATERIALIZED_NPM_INSTANCE_OBLIGATIONS_OBSERVED',
        'sourceOriginObservationDigest': source_origin_digest, 'resolvedStateKey': resolved_state_key,
        'approvedLockSha256': plan['approvedLockSha256'], 'obligationPlanDigest': plan['obligationPlanDigest'],
        'materializedTreeObservationDigest': _canonical_hash({'instances': rows, 'edges': edges}),
        'instanceCount': len(rows), 'heldInstanceCount': sum(row['held'] for row in rows),
        'protectedEdgeCount': len(edges), 'changedInstanceCount': plan['changedInstanceCount'],
        'unknownCount': 0, 'violations': [], 'payloadAuthenticity': 'NOT_ATTESTED',
        'scope': 'PHYSICAL_INSTANCE_MANIFESTS_AND_SUPPORTED_NODE_EDGES_AT_BOUNDARIES', 'fullAcceptance': False}
