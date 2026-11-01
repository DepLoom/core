"""Explicit project child environment, distinct from host transport metadata.

No ambient mutation or stored secret values. Legacy proof semantics are unchanged.
V2 omits exactly one transport-owned key from ACTUAL child mappings, not merely
from a fingerprint. Native PID/Job supervision remains the owning boundary.
"""
from __future__ import annotations
import hashlib,json,os
from types import MappingProxyType

LEGACY='LEGACY_INHERITED_ENV_V1'
V2='HOST_OWNED_PROJECT_EXECUTION_ENV_V1'
TRANSPORT_KEY='CODEX_TOOL_CALL_ID'

class ProjectExecutionEnvironmentError(RuntimeError):pass


def _normalized(source,windows):
    result={}
    for key,value in source.items():
        if (not isinstance(key,str) or not key or '=' in key or '\x00' in key
                or not isinstance(value,str) or '\x00' in value):
            raise ProjectExecutionEnvironmentError('PROJECT_ENVIRONMENT_ENTRY_INVALID')
        name=key.upper() if windows else key
        if name in result:raise ProjectExecutionEnvironmentError('PROJECT_ENVIRONMENT_CASE_COLLISION')
        result[name]=value
    return result


def project_execution_environment(host_environment,*,contract=LEGACY,overrides=None,windows=None):
    if contract==LEGACY:
        env=dict(host_environment);env.update(overrides or {});return env
    if contract!=V2:raise ProjectExecutionEnvironmentError('PROJECT_ENVIRONMENT_CONTRACT_UNSUPPORTED')
    windows=os.name=='nt' if windows is None else windows
    if type(windows) is not bool:raise ProjectExecutionEnvironmentError('PROJECT_ENVIRONMENT_PLATFORM_INVALID')
    env=_normalized(host_environment,windows);env.update(_normalized(overrides or {},windows))
    env.pop(TRANSPORT_KEY,None)
    return MappingProxyType(env)


def workspace_execution_environment(host_environment,cache_dir,*,contract=LEGACY):
    overrides=dict(CI='1',NX_DAEMON='false',npm_config_offline='true',
        npm_config_ignore_scripts='true',npm_config_strict_peer_deps='true',
        npm_config_engine_strict='true',npm_config_legacy_peer_deps='false',
        npm_config_force='false',npm_config_audit='false',npm_config_fund='false',
        npm_config_update_notifier='false',npm_config_cache=str(cache_dir))
    return project_execution_environment(host_environment,contract=contract,overrides=overrides)


def project_environment_fingerprint(actual_environment,*,contract=LEGACY):
    if contract==LEGACY:
        from verification_proof import environment_snapshot_fingerprint
        return environment_snapshot_fingerprint(actual_environment)
    if contract!=V2:raise ProjectExecutionEnvironmentError('PROJECT_ENVIRONMENT_CONTRACT_UNSUPPORTED')
    env=_normalized(actual_environment,os.name=='nt')
    # FAIL rather than silently hashing a projection while a child still gets ID.
    if TRANSPORT_KEY in env:raise ProjectExecutionEnvironmentError('PROJECT_TRANSPORT_ENVIRONMENT_FORWARDED')
    from substrate_identity import tool_build_id
    rows=[(k,hashlib.sha256(v.encode('utf-8')).hexdigest()) for k,v in sorted(env.items())]
    payload={'schema':'project_execution_environment_v2','contract':V2,'toolBuildId':tool_build_id(),'environment':rows}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()[:32]


def project_environment_observation(actual_environment,*,contract=LEGACY):
    if contract==LEGACY:return None
    return {'schemaVersion':2,'contract':V2,'origin':'EXPLICIT_OWNER_CHILD_MAPPING',
        'environmentDigest':project_environment_fingerprint(actual_environment,contract=contract),
        'removedTransportNames':[TRANSPORT_KEY],'transportValueForwarded':False,
        'arbitraryDescendantEnvironmentClosureVerified':False}
