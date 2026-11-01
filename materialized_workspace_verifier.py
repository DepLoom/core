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
        commands, cache_dir, deadline, final_profile_digest, environment=None, materialize=False,
        environment_contract='LEGACY_INHERITED_ENV_V1', trusted_pre_popen_guard=None):
    """Freshly check THIS authorized workspace; optional cold-only npm-ci.

    No caller-provided evidence, reusable command PASS or previous prepared tree
    is accepted. Commands and installation permission belong to the host caller.
    A crash before the returned observation is durably closed requires fresh
    verification of the same attempt, never a manufactured resumed PASS.
    """
    from baseline_constraint_verifier import (project_check_command_argv,
        observed_resolved_assignment, observed_resolved_hash)
    operation_started=time.monotonic()
    operations=[]
    def fail(code):
        error=MaterializedWorkspaceVerificationError(code)
        error.operation_observations=tuple(operations)
        raise error
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
    from project_execution_environment import (workspace_execution_environment,
        project_environment_fingerprint,project_environment_observation)
    if environment_contract=='HOST_OWNED_PROJECT_EXECUTION_ENV_V1' and (os.name!='nt' or str(project).startswith('\\\\')):
        fail('CURRENT_WORKSPACE_ENVIRONMENT_BOUNDARY_UNSUPPORTED')
    env=workspace_execution_environment(os.environ if environment is None else environment,cache,
        contract=environment_contract)
    if any(str(env.get(k,'')).strip() for k in ('NODE_OPTIONS','NODE_PATH')):
        fail('CURRENT_WORKSPACE_EXTERNAL_NODE_LOADER_UNPROVEN')
    node=shutil.which('node',path=env.get('PATH'));npm=Path(node).parent/'node_modules/npm/bin/npm-cli.js' if node else None
    if not node or not npm.is_file():fail('CURRENT_WORKSPACE_TOOLCHAIN_UNAVAILABLE')
    tools={'nodeSha256':_sha(Path(node).read_bytes()),'npmCliSha256':_sha(npm.read_bytes())}
    lock=(project/'package-lock.json').read_bytes()
    if _sha(lock)!=dependency_plan['approvedLockSha256']:fail('CURRENT_WORKSPACE_APPROVED_LOCK_MISMATCH')
    def run(argv,label,command_index=None):
        started=time.monotonic()
        launch_options={}
        if environment_contract=='HOST_OWNED_PROJECT_EXECUTION_ENV_V1':
            launch_options['expected_project_environment_digest']=project_environment_fingerprint(env,contract=environment_contract)
        if trusted_pre_popen_guard is not None:
            launch_options.update(trusted_pre_popen_guard=trusted_pre_popen_guard,
                trusted_pre_popen_context={'invocationId':invocation_id,'operation':'strict-frozen-install' if command_index is None else 'project-command',
                    'commandIndex':command_index,'sealedCommandHash':None if command_index is None else _sha(commands[command_index-1].encode()),
                    'profileDigest':final_profile_digest,'argvDigest':_digest(argv)})
        x=run_supervised(argv,project,timeout_seconds=remaining(),base_env=env,
            progress_label=label,max_output_bytes=65536,**launch_options)
        s=getattr(x,'supervision',None)
        operations.append({'operation':'strict-frozen-install' if command_index is None else 'project-command',
            'commandIndex':command_index,'argvDigest':_digest(argv),'elapsedStartMs':int((started-operation_started)*1000),
            'durationMs':int((time.monotonic()-started)*1000),'returnCode':x.returncode,
            'supervision':getattr(s,'quality',None),'descendantsRemaining':getattr(s,'descendants_remaining',None),
            'timedOut':bool(getattr(x,'timed_out',False)),'cancelled':bool(getattr(x,'cancelled',False))})
        if launch_options:
            from project_execution_environment import native_launch_observation_matches
            launch=getattr(x,'project_execution_environment',None)
            if not native_launch_observation_matches(launch,launch_options['expected_project_environment_digest'],_digest(str(project))):
                fail('CURRENT_WORKSPACE_ACTUAL_ENVIRONMENT_UNPROVEN')
            operations[-1]['projectExecutionEnvironment']=dict(launch)
        witness=getattr(x,'guarded_spawn_witness',None)
        if witness is not None:operations[-1]['guardedSpawnWitness']=dict(witness)
        remaining()
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
        auxiliary_observations=[]
        def tree(phase):
            def auxiliary(rows):
                auxiliary_observations.append({'phase':phase,'directories':rows,'arbitraryFilesystemSemanticsVerified':False})
            try:
                return observe_npm_dependency_obligations(project,dependency_plan,
                    source_origin_digest=_digest(origin),resolved_state_key=state.key,
                    deadline=time.monotonic()+max(0,deadline-time.time()),auxiliary_directory_observer=auxiliary)
            except Exception as exc:
                exc.operation_observations=tuple(operations)
                raise
        initial=tree('initial');rows=[]
        if not materialize:installation['status']='EXISTING_TREE_PHYSICALLY_OBSERVED'
        for index,command in enumerate(commands,1):
            source_guard();before=tree('before-command-'+str(index))
            if before!=initial:fail('CURRENT_WORKSPACE_TREE_CHANGED')
            inline=pinned_inline_node_invocation(command,env)
            argv=inline['argv'] if inline else project_check_command_argv(command,env)
            result=run(argv,'current-workspace project check',index)
            source_guard();after=tree('after-command-'+str(index))
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
        source_guard();final=tree('final')
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
            'environmentDigest':project_environment_fingerprint(env,contract=environment_contract),'commandObservations':rows,
            'installation':installation,
            'currentWorkspaceVerified':False,'checkpointPublished':False,'fullAcceptance':False}
    remaining()
    result['sourceSnapshotCleanupClosed']=True
    execution_environment=project_environment_observation(env,contract=environment_contract)
    if execution_environment is not None:result['projectExecutionEnvironment']=execution_environment
    result['ownedCleanupConfirmed']=True
    result['auxiliaryDirectoryObservations']=auxiliary_observations
    result['arbitraryFilesystemSemanticsVerified']=False
    result['ownerOperationObservations']=operations
    result['ownerElapsedMs']=int((time.monotonic()-operation_started)*1000)
    return result
