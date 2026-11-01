"""Fresh checks of the actual caller-authorized npm workspace.

This owner does not issue permissions or publish checkpoints. Unlike the private
candidate verifier it never substitutes a prepared copy for the supplied working
workspace. The caller must explicitly authorize npm-ci and the pinned commands.
Only supported physical manifest/edge boundaries are observed, not package
payload/.bin integrity, arbitrary JS semantics or external input closure.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import time
import re
import uuid

from source_snapshot import (verification_source_snapshot_scope,
    validate_source_snapshot, source_snapshot_live_source_continuity)
from resolved_dependency_state import (capture_resolved_dependency_state,
    observe_npm_dependency_obligations,npm_root_assignment_from_obligations)
from verification_process_supervisor import run_supervised
from verification_stage_checkpoint import pinned_inline_node_invocation
from verification_proof import environment_snapshot_fingerprint


class MaterializedWorkspaceVerificationError(RuntimeError):
    """Unproven current state; never a learned solver incompatibility."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_current_workspace(project_dir, *, expected_source_key, dependency_plan,
        commands, cache_dir, deadline, final_profile_digest, environment=None, materialize=False):
    """Freshly check THIS authorized workspace; optional cold-only npm-ci.

    No caller-provided evidence, reusable command PASS or previous prepared tree
    is accepted. Commands and installation permission belong to the host caller.
    A crash before the returned observation is durably closed requires fresh
    verification of the same attempt, never a manufactured resumed PASS.
    """
    from baseline_constraint_verifier import (project_check_command_argv,
        observed_resolved_assignment, observed_resolved_hash)
    def fail(code):
        raise MaterializedWorkspaceVerificationError(code)
    def remaining():
        value=deadline-time.time()
        if value <= 0: fail('CURRENT_WORKSPACE_DEADLINE_EXCEEDED')
        return max(1, int(value))
    if (isinstance(deadline,bool) or not isinstance(deadline,(int,float))
            or not math.isfinite(deadline)):
        fail('CURRENT_WORKSPACE_INVALID_DEADLINE')
    remaining()
    if not isinstance(final_profile_digest,str) or re.fullmatch('[0-9a-f]{64}',final_profile_digest) is None:
        fail('CURRENT_WORKSPACE_FINAL_PROFILE_UNPROVEN')
    invocation_id=uuid.uuid4().hex
    if type(materialize) is not bool:fail('CURRENT_WORKSPACE_INSTALL_POLICY_UNPROVEN')
    if (not isinstance(dependency_plan,dict)
            or type(dependency_plan.get('schemaVersion')) is not int
            or dependency_plan.get('schemaVersion') != 1
            or dependency_plan.get('obligationPlanDigest') != _digest({k:v for k,v in dependency_plan.items() if k!='obligationPlanDigest'})):
        fail('CURRENT_WORKSPACE_PLAN_UNPROVEN')
    if (not isinstance(commands,(tuple,list)) or not 1<=len(commands)<=64
            or any(not isinstance(c,str) or not c.strip() or len(c)>4096 for c in commands)):
        fail('CURRENT_WORKSPACE_PROFILE_UNPROVEN')
    project=Path(project_dir).absolute();cache=Path(cache_dir).absolute()
    if (project.is_symlink() or cache.is_symlink()
            or (hasattr(project,'is_junction') and project.is_junction())
            or (hasattr(cache,'is_junction') and cache.is_junction())
            or not project.is_dir() or not cache.is_dir()
            or cache.resolve().is_relative_to(project.resolve())):
        fail('CURRENT_WORKSPACE_PATH_UNPROVEN')
    project=project.resolve();cache=cache.resolve()
    modules=project/'node_modules'
    if modules.is_symlink() or (hasattr(modules,'is_junction') and modules.is_junction()):
        fail('CURRENT_WORKSPACE_DEPENDENCY_ROOT_REPARSE_UNPROVEN')
    if materialize and modules.exists() and (not modules.is_dir() or any(modules.iterdir())):
        fail('CURRENT_WORKSPACE_EXISTING_TREE_REQUIRES_RECOVERABLE_STAGING')
    env=dict(os.environ if environment is None else environment)
    env.update(CI='1',NX_DAEMON='false',npm_config_offline='true',
        npm_config_ignore_scripts='true',npm_config_strict_peer_deps='true',
        npm_config_engine_strict='true',npm_config_legacy_peer_deps='false',
        npm_config_force='false',npm_config_audit='false',npm_config_fund='false',
        npm_config_update_notifier='false',npm_config_cache=str(cache))
    if any(str(env.get(k,'')).strip() for k in ('NODE_OPTIONS','NODE_PATH')):
        fail('CURRENT_WORKSPACE_EXTERNAL_NODE_LOADER_UNPROVEN')
    node=shutil.which('node',path=env.get('PATH'));npm=Path(node).parent/'node_modules/npm/bin/npm-cli.js' if node else None
    if not node or not npm.is_file():fail('CURRENT_WORKSPACE_TOOLCHAIN_UNAVAILABLE')
    tools={'nodeSha256':_sha(Path(node).read_bytes()),'npmCliSha256':_sha(npm.read_bytes())}
    lock=(project/'package-lock.json').read_bytes()
    if _sha(lock)!=dependency_plan['approvedLockSha256']:fail('CURRENT_WORKSPACE_APPROVED_LOCK_MISMATCH')
    def run(argv,label):
        x=run_supervised(argv,project,timeout_seconds=remaining(),base_env=env,
            progress_label=label,max_output_bytes=65536)
        remaining()
        s=getattr(x,'supervision',None)
        if (getattr(s,'quality',None)!='guaranteed-tree'
                or getattr(s,'descendants_remaining',None)!=0
                or getattr(x,'timed_out',False) or getattr(x,'cancelled',False)):
            fail('CURRENT_WORKSPACE_PROCESS_CLOSURE_UNPROVEN')
        return x
    with verification_source_snapshot_scope(project,timeout_seconds=remaining(),strict_cleanup=True) as snapshot:
        if snapshot.key!=expected_source_key:fail('CURRENT_WORKSPACE_SOURCE_MISMATCH')
        def source_guard():
            remaining();validate_source_snapshot(snapshot,timeout_seconds=remaining())
            if (not source_snapshot_live_source_continuity(snapshot,timeout_seconds=remaining())
                    or (project/'package-lock.json').read_bytes()!=lock
                    or tools!={'nodeSha256':_sha(Path(node).read_bytes()),'npmCliSha256':_sha(npm.read_bytes())}):
                fail('CURRENT_WORKSPACE_INPUT_CHANGED')
        source_guard()
        installation={'status':'EXISTING_TREE_REQUIRES_PHYSICAL_OBSERVATION','scriptsEnabled':False}
        if materialize:
            install=run([node,str(npm),'ci','--offline','--ignore-scripts','--strict-peer-deps',
                '--engine-strict','--force=false','--legacy-peer-deps=false','--no-audit','--no-fund',
                '--cache',str(cache)],'current-workspace frozen install')
            source_guard()
            if install.returncode!=0:fail('CURRENT_WORKSPACE_INSTALL_NOT_VERIFIED')
            installation={'status':'FRESH_COLD_FROZEN_INSTALL_OBSERVED','scriptsEnabled':False,
                'supervision':'guaranteed-tree','stdoutDigest':_sha((install.stdout or '').encode())}
        roots=npm_root_assignment_from_obligations(dependency_plan)
        observed=observed_resolved_assignment(project,roots)
        state=capture_resolved_dependency_state(project,manager='npm',
            resolver_input_key=_digest({'sourceKey':snapshot.key,'plan':dependency_plan['obligationPlanDigest'],
                'toolchain':tools,'environment':environment_snapshot_fingerprint(env)}),
            observed_resolved_hash=observed_resolved_hash(observed),proof_cache_dir=None)
        origin={'schemaVersion':1,'scope':'CURRENT_HOST_WORKSPACE',
            'inputSourceSnapshotKey':snapshot.key,'workspacePathDigest':_digest(str(project)),
            'resolvedLockfileHash':state.lockfile_hash,'toolchain':tools}
        def tree():
            return observe_npm_dependency_obligations(project,dependency_plan,
                source_origin_digest=_digest(origin),resolved_state_key=state.key,
                deadline=time.monotonic()+max(0,deadline-time.time()))
        initial=tree();rows=[]
        if not materialize:installation['status']='EXISTING_TREE_PHYSICALLY_OBSERVED'
        for index,command in enumerate(commands,1):
            source_guard();before=tree()
            if before!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
            inline=pinned_inline_node_invocation(command,env)
            argv=inline['argv'] if inline else project_check_command_argv(command,env)
            result=run(argv,'current-workspace project check')
            source_guard();after=tree()
            if after!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
            if result.returncode!=0:fail('CURRENT_WORKSPACE_COMMAND_FAILED')
            rows.append({'commandIndex':index,'commandDigest':_sha(command.encode()),
                'freshCommandInvocationId':invocation_id,'finalVerificationProfileDigest':final_profile_digest,
                'commandBoundaryGuard':'PRE_POST_OBSERVED',
                'status':'PASS','origin':'EXECUTED_FRESH','returnCode':0,'supervision':'guaranteed-tree',
                'sourceSnapshotKey':snapshot.key,'resolvedStateKey':state.key,
                'obligationPlanDigest':dependency_plan['obligationPlanDigest'],
                'materializedTreeObservationDigest':initial['materializedTreeObservationDigest'],
                'inlineExecution':inline,'stdoutDigest':_sha((result.stdout or '').encode())})
        source_guard();final=tree()
        if final!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
        result={'schemaVersion':1,'status':'CURRENT_WORKSPACE_PROFILE_OBSERVED',
            'authority':'NON_REUSABLE_CORE_CURRENT_WORKSPACE_OBSERVATION',
            'executionScope':'REGISTERED_CURRENT_WORKSPACE','freshCommandInvocationId':invocation_id,
            'finalVerificationProfileDigest':final_profile_digest,
            'deliveredSourceObservationDigest':_digest(origin),
            'liveMaterializedTreeObservationDigest':final['materializedTreeObservationDigest'],
            'finalBoundaryObserved':True,
            'sourceSnapshotKey':snapshot.key,'workspacePathDigest':_digest(str(project)),
            'resolvedStateKey':state.key,'resolvedLockfileHash':state.lockfile_hash,
            'materializedSourceOrigin':origin,'materializedDependencyObligations':final,
            'environmentDigest':environment_snapshot_fingerprint(env),'commandObservations':rows,
            'installation':installation,
            'currentWorkspaceVerified':False,'checkpointPublished':False,'fullAcceptance':False}
    remaining()
    result['sourceSnapshotCleanupClosed']=True
    result['ownedCleanupConfirmed']=True
    return result
