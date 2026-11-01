"""Non-reusable observations from the verifier's own physical execution branch.

These events never enter proof caches and never authorize goal acceptance.
A trusted consumer must wait for the outer call to return and validate identities.
"""
from __future__ import annotations
import copy
from contextvars import ContextVar
import hashlib
import uuid

_CURRENT=ContextVar("verification_invocation_observer",default=None)

class InvocationObservationError(RuntimeError):pass

def _digest(text):return hashlib.sha256(str(text).encode("utf-8",errors="replace")).hexdigest()

def _result_identity(result):
    return {name:str(getattr(result,name,"") or "") for name in (
        "verified_source_snapshot_key","verified_assignment_fingerprint","resolved_state_key",
        "resolved_lockfile_hash","observed_resolved_hash")}

class InvocationObservation:
    def __init__(self,callback,assignment_fingerprint,commands):
        if not callable(callback):raise TypeError("invocation_observer must be callable")
        self.callback=callback;self.assignment=assignment_fingerprint
        self.commands=tuple(commands);self.events=[];self.cleanups=[];self.cleanup_failures=[];self.finished=False;self.failed=False;self.identity=None
        self.id=uuid.uuid4().hex
    def emit(self,event):
        payload={"schemaVersion":2,"invocationId":self.id,"sequence":len(self.events)+1,
                 "authority":"NON_REUSABLE_INVOCATION_OBSERVATION","reuseAllowed":False,"fullAcceptance":False,**event}
        self.events.append(copy.deepcopy(payload))
        try:self.callback(copy.deepcopy(payload))
        except BaseException as exc:
            self.failed=True
            raise InvocationObservationError("INVOCATION_OBSERVER_FAILED") from exc
    def command(self,index,command,result=None,guarded=False,origin="EXECUTED_FRESH",identities=None):
        if self.failed:return
        rc=getattr(result,"returncode",None)
        supervision=getattr(result,"supervision",None)
        quality=str(getattr(supervision,"quality","") or "")
        timeout=bool(getattr(result,"timed_out",False));cancelled=bool(getattr(result,"cancelled",False))
        guaranteed=quality=="guaranteed-tree" and getattr(supervision,"descendants_remaining",None)==0
        status=("REUSED_NOT_FRESH" if origin=="REUSED" else "UNKNOWN" if timeout or cancelled or not guaranteed
                else "FAIL" if type(rc) is int and rc>0 else "PASS" if type(rc) is int and rc==0 and guarded else "UNKNOWN")
        self.emit({"type":"COMMAND_COMPLETED","commandIndex":index,"commandDigest":_digest(command),
                   "origin":origin,"status":status,"returnCode":rc,"timedOut":timeout,"cancelled":cancelled,
                   "supervision":quality,"guardsPassed":bool(guarded),"identities":dict(identities or {}),
                   "stdoutDigest":_digest(getattr(result,"stdout","") or "") if result is not None else None})
    def finish(self,result=None,error=None,before_cleanup=False):
        if self.finished or self.failed:return
        self.finished=True;self.identity=_result_identity(result) if result is not None else {}
        observed=[e for e in self.events if e["type"]=="COMMAND_COMPLETED"]
        fresh=[];missing=[]
        for index,command in enumerate(self.commands,1):
            rows=[e for e in observed if e["commandIndex"]==index and e["commandDigest"]==_digest(command)]
            identities=rows[0].get("identities",{}) if len(rows)==1 else {}
            aligned=bool(self.identity) and identities.get("sourceSnapshotKey")==self.identity.get("verified_source_snapshot_key") and identities.get("resolvedStateKey")==self.identity.get("resolved_state_key") and identities.get("resolvedLockfileHash")==self.identity.get("resolved_lockfile_hash") and identities.get("targetOnlyAssignmentFingerprint")==self.assignment
            if len(rows)==1 and rows[0]["origin"]=="EXECUTED_FRESH" and rows[0]["status"]=="PASS" and aligned:fresh.append(index)
            else:missing.append(index)
        identity_complete=bool(self.identity) and all(self.identity.values()) and self.identity.get("verified_assignment_fingerprint")==self.assignment
        complete=bool(result is not None and getattr(result,"ok",False) and getattr(result,"kind","")=="passed" and not error and not missing and self.commands and identity_complete and before_cleanup and not self.cleanup_failures)
        self.emit({"type":"INVOCATION_RESULT_OBSERVED","outcome":str(getattr(result,"kind","unknown")),
                   "status":"RESULT_OBSERVED_COMPLETE" if complete else "INCOMPLETE_UNKNOWN",
                   "beforePrivateWorkspaceDeletion":before_cleanup,"sourceGuardsActive":"NOT_ATTESTED",
                   "invocationReturned":False,"identities":self.identity,
                   "targetOnlyAssignmentFingerprint":self.assignment,"requiredCommandCount":len(self.commands),
                   "freshPassedCommandIndexes":fresh,"unconfirmedCommandIndexes":missing,
                   "errorType":type(error).__name__ if error is not None else None,
                   "localWorkspace":str(getattr(result,"workspace","") or "") if result is not None else "",
                   "materializedSourceOrigin":copy.deepcopy(getattr(result,"materialized_source_origin",{}) or {}),
                   "metadataNecessityCheck":"UNKNOWN",
                   "publicationEligibility":"FORBIDDEN_UNTIL_OUTER_CALL_RETURNS"})

def observe_command(index,command,result,*,guarded,identities):
    state=_CURRENT.get()
    if state is not None:state.command(index,command,result,guarded=guarded,identities=identities)

def observe_reused_command(index,command,identities):
    state=_CURRENT.get()
    if state is not None:state.command(index,command,origin="REUSED",identities=identities)

def observe_reused_profile(commands,identities):
    for index,command in enumerate(commands,1):observe_reused_command(index,command,identities)

def defer_workspace_cleanup(cleanup):
    state=_CURRENT.get()
    if state is None:return False
    state.cleanups.append(cleanup)
    return True

def guarded_cleanup(cleanup_guard,target):
    state=_CURRENT.get()
    try:result=cleanup_guard(target)
    except Exception as exc:
        if state is not None:state.cleanup_failures.append(exc)
        raise
    if state is not None and (getattr(result,"errors",()) or getattr(result,"mutations",())):
        state.cleanup_failures.append(InvocationObservationError("GUARDED_CLEANUP_RESULT_NOT_CLEAN"))
    return result


def close_owned_resources(guarded_roots,cleanup_guard,source_binding,cleanup_workspace,cleanup_deferred,event):
    """Release all owner resources; legacy logging never grants observed success."""
    try:
        for guarded_root in guarded_roots:
            try:guarded_cleanup(cleanup_guard,guarded_root)
            except Exception as exc:
                event("verify.project-check.guard-cleanup-failed",detail=str(exc),workspace=str(guarded_root))
    finally:
        try:source_binding.close()
        finally:
            if not cleanup_deferred:cleanup_workspace()


def run_observed(callback,assignment_fingerprint,commands,action):
    state=InvocationObservation(callback,assignment_fingerprint,commands);token=_CURRENT.set(state)
    primary_error=None
    try:
        try:result=action()
        except BaseException as exc:
            try:state.finish(error=exc)
            except BaseException as observation_error:
                exc.add_note("Invocation observation also failed: "+type(observation_error).__name__)
            raise
        state.finish(result,before_cleanup=bool(state.cleanups))
        if state.identity!=_result_identity(result):
            raise InvocationObservationError("RESULT_IDENTITY_CHANGED_AFTER_OBSERVATION")
        return result
    except BaseException as exc:
        primary_error=exc
        raise
    finally:
        cleanup_error=state.cleanup_failures[0] if state.cleanup_failures else None
        try:
            for cleanup in reversed(state.cleanups):
                try:cleanup()
                except BaseException as exc:cleanup_error=exc
        finally:_CURRENT.reset(token)
        if cleanup_error is not None:
            if primary_error is not None:
                primary_error.add_note("Owned invocation cleanup also failed: "+type(cleanup_error).__name__)
            else:
                raise InvocationObservationError("OBSERVED_WORKSPACE_CLEANUP_FAILED") from cleanup_error
