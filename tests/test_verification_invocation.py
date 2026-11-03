from __future__ import annotations
import os
import ast
import asyncio
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import baseline_constraint_verifier as verifier
from verification_invocation import (InvocationObservationError,run_observed,observe_command,
    observe_reused_profile,defer_workspace_cleanup)

ASSIGNMENT={"demo":"2.0.0"}
FINGERPRINT=verifier.assignment_fingerprint(ASSIGNMENT)
COMMAND="python engineering-control"

def result(ok=True):
    return verifier.BaselineVerifyResult(ok,"passed" if ok else "project","engineering fixture, not project evidence",
        verified_source_snapshot_key="a"*32,verified_assignment_fingerprint=FINGERPRINT,
        resolved_state_key="b"*64,resolved_lockfile_hash="c"*64,observed_resolved_hash="d"*64)

def identities():
    return {"sourceSnapshotKey":"a"*32,"targetOnlyAssignmentFingerprint":FINGERPRINT,"resolvedStateKey":"b"*64,"resolvedLockfileHash":"c"*64}

def supervised(rc=0):
    return SimpleNamespace(returncode=rc,stdout="fixture output",timed_out=False,cancelled=False,
        supervision=SimpleNamespace(quality="guaranteed-tree",descendants_remaining=0))

class VerificationInvocationTests(unittest.TestCase):
    def test_default_wrapper_delegates_without_changing_result_or_publication(self):
        expected=result();config=verifier.BaselineVerifyConfig(verification_purpose="intermediate-candidate")
        with patch.object(verifier,"_verify_assignment_before_invocation_observer",return_value=expected) as implementation:
            self.assertIs(verifier.verify_assignment(Path.cwd(),ASSIGNMENT,config=config),expected)
            self.assertNotIn("invocation_observer",implementation.call_args.kwargs)
        self.assertEqual(verifier._durable_prepared_publication_policy(config),(False,"intermediate-role-private"))
    @unittest.skipUnless(os.name=='nt','Native guaranteed-tree observation is Windows-only')
    def test_actual_supervisor_observation_precedes_deferred_workspace_cleanup(self):
        from verification_process_supervisor import run_supervised
        events=[]
        with tempfile.TemporaryDirectory() as raw:
            trial=Path(raw)/"trial";trial.mkdir()
            expected=result()
            expected=__import__('dataclasses').replace(expected,workspace=str(trial))
            def action():
                self.assertTrue(defer_workspace_cleanup(lambda:shutil.rmtree(trial)))
                observed=run_supervised([sys.executable,"-c","print('engineering control')"],trial,timeout_seconds=5)
                observe_command(1,COMMAND,observed,guarded=True,identities=identities())
                return expected
            def callback(event):
                if event["type"]=="INVOCATION_RESULT_OBSERVED":self.assertTrue(trial.exists())
                events.append(event)
            self.assertIs(run_observed(callback,FINGERPRINT,[COMMAND],action),expected)
            self.assertFalse(trial.exists())
        self.assertEqual(events[-1]["status"],"RESULT_OBSERVED_COMPLETE")
        self.assertTrue(events[-1]["beforePrivateWorkspaceDeletion"])
        self.assertFalse(events[-1]["fullAcceptance"])
        self.assertEqual(events[-1]["metadataNecessityCheck"],"UNKNOWN")
    def test_callback_return_and_payload_mutation_cannot_change_owner_result(self):
        expected=result(False);events=[]
        def callback(event):
            event["fullAcceptance"]=True;events.append(event);return {"passed":True}
        self.assertIs(run_observed(callback,FINGERPRINT,[COMMAND],lambda:expected),expected)
        self.assertFalse(expected.ok)
        self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
    def test_reused_or_missing_command_is_not_fresh_pass(self):
        for reuse in [True,False]:
            events=[]
            def action():
                defer_workspace_cleanup(lambda:None)
                if reuse:observe_reused_profile([COMMAND],identities())
                return result()
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
            self.assertEqual(events[-1]["unconfirmedCommandIndexes"],[1])
            self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
            if reuse:self.assertEqual(events[0]["origin"],"REUSED")
    def test_source_and_lock_mismatch_do_not_complete_observation(self):
        for key in ["sourceSnapshotKey","resolvedStateKey","resolvedLockfileHash","targetOnlyAssignmentFingerprint"]:
            events=[]
            def action():
                defer_workspace_cleanup(lambda:None);wrong={**identities(),key:"wrong"}
                observe_command(1,COMMAND,supervised(),guarded=True,identities=wrong);return result()
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
            self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
    def test_missing_guards_or_supervision_cannot_pass_command(self):
        for guarded,quality in [(False,"guaranteed-tree"),(True,"unknown"),(True,"best-effort")]:
            events=[]
            def action():
                defer_workspace_cleanup(lambda:None);process=supervised();process.supervision.quality=quality
                observe_command(1,COMMAND,process,guarded=guarded,identities=identities());return result()
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
            self.assertEqual(events[0]["status"],"UNKNOWN")
    def test_callback_exception_still_cleans_workspace_and_has_no_successful_final(self):
        cleanup=[];events=[]
        def callback(event):events.append(event);raise RuntimeError("test callback failure")
        def action():
            defer_workspace_cleanup(lambda:cleanup.append(True));observe_command(1,COMMAND,supervised(),guarded=True,identities=identities());return result()
        with self.assertRaises(InvocationObservationError):run_observed(callback,FINGERPRINT,[COMMAND],action)
        self.assertEqual(cleanup,[True]);self.assertFalse(any(e["type"]=="INVOCATION_RESULT_OBSERVED" for e in events))
    def test_cancellation_and_early_exception_never_leave_successful_final(self):
        for error in [asyncio.CancelledError(),RuntimeError("early control")]:
            cleanup=[];events=[]
            def action():defer_workspace_cleanup(lambda:cleanup.append(True));raise error
            with self.assertRaises(type(error)):run_observed(events.append,FINGERPRINT,[COMMAND],action)
            self.assertEqual(cleanup,[True]);self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
    def test_duplicate_command_attempts_are_not_silently_collapsed(self):
        events=[]
        def action():
            defer_workspace_cleanup(lambda:None)
            for _ in range(2):observe_command(1,COMMAND,supervised(),guarded=True,identities=identities())
            return result()
        run_observed(events.append,FINGERPRINT,[COMMAND],action)
        self.assertEqual(events[-1]["unconfirmedCommandIndexes"],[1])
    def test_context_restored_after_callback_failure(self):
        def action():defer_workspace_cleanup(lambda:None);return result()
        with self.assertRaises(InvocationObservationError):run_observed(lambda e:(_ for _ in ()).throw(RuntimeError()),FINGERPRINT,[COMMAND],action)
        self.assertFalse(defer_workspace_cleanup(lambda:None))
    def test_real_core_hooks_use_supervised_result_not_telemetry(self):
        source=Path(verifier.__file__).read_text(encoding="utf-8");tree=ast.parse(source)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="_observe_invocation_command"]
        self.assertEqual(len(calls),1);self.assertEqual(calls[0].args[2].id,"check_result")
        guard=next(k.value for k in calls[0].keywords if k.arg=="guarded")
        names={n.id for n in ast.walk(guard) if isinstance(n,ast.Name)}
        self.assertTrue({"command_pass_verified","lower_check_clean","workspace_guard_started","workspace_changes"}.issubset(names))
        import verification_invocation
        self.assertNotIn("emit_verification_event",Path(verification_invocation.__file__).read_text())

if __name__=="__main__":unittest.main()
