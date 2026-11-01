"""Engineering lifecycle controls; never real project acceptance."""
import tempfile
import threading
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import baseline_constraint_verifier as verifier
from verification_invocation import run_observed,observe_command,defer_workspace_cleanup,InvocationObservationError
from test_verification_invocation import COMMAND,FINGERPRINT,identities,result,supervised

class ObserverLifecycleTests(unittest.TestCase):
    def test_cleanup_failure_after_complete_preliminary_result_drains_other_resources(self):
        events=[];released=[]
        def fail_cleanup():raise OSError("injected owned cleanup failure")
        def action():
            defer_workspace_cleanup(lambda:released.append("other"))
            defer_workspace_cleanup(fail_cleanup)
            observe_command(1,COMMAND,supervised(),guarded=True,identities=identities())
            return result()
        with self.assertRaisesRegex(InvocationObservationError,"CLEANUP_FAILED"):
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
        self.assertEqual(released,["other"])
        final=events[-1]
        self.assertEqual(final["type"],"INVOCATION_RESULT_OBSERVED")
        self.assertEqual(final["status"],"RESULT_OBSERVED_COMPLETE")
        self.assertFalse(final["invocationReturned"])
        self.assertEqual(final["publicationEligibility"],"FORBIDDEN_UNTIL_OUTER_CALL_RETURNS")
        self.assertFalse(defer_workspace_cleanup(lambda:None))
    def test_final_callback_exception_cleans_all_owned_resources(self):
        released=[]
        def action():
            defer_workspace_cleanup(lambda:released.append(True))
            observe_command(1,COMMAND,supervised(),guarded=True,identities=identities())
            return result()
        def callback(event):
            if event["type"]=="INVOCATION_RESULT_OBSERVED":raise ValueError("injected final callback error")
        with self.assertRaisesRegex(InvocationObservationError,"OBSERVER_FAILED"):
            run_observed(callback,FINGERPRINT,[COMMAND],action)
        self.assertEqual(released,[True])
    def test_primary_exception_is_preserved_when_observer_and_cleanup_also_fail(self):
        primary=ValueError("primary execution failure")
        def cleanup():raise OSError("secondary cleanup failure")
        def action():defer_workspace_cleanup(cleanup);raise primary
        def callback(event):raise RuntimeError("secondary callback failure")
        with self.assertRaises(ValueError) as caught:run_observed(callback,FINGERPRINT,[COMMAND],action)
        self.assertIs(caught.exception,primary)
        self.assertEqual(len(primary.__notes__),2)
        self.assertIn("observation also failed",primary.__notes__[0])
        self.assertIn("cleanup also failed",primary.__notes__[1])
        self.assertFalse(defer_workspace_cleanup(lambda:None))
    def test_thread_without_context_cannot_invent_command_execution(self):
        events=[]
        def action():
            defer_workspace_cleanup(lambda:None)
            thread=threading.Thread(target=lambda:observe_command(1,COMMAND,supervised(),guarded=True,identities=identities()))
            thread.start();thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            return result()
        run_observed(events.append,FINGERPRINT,[COMMAND],action)
        self.assertEqual(len(events),1)
        self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(events[-1]["unconfirmedCommandIndexes"],[1])
    def test_real_owner_guarded_clone_cleanup_error_blocks_observed_success(self):
        released=[];events=[]
        def bad_guard(path):released.append("guard");raise OSError("injected guarded clone cleanup failure")
        def action():
            defer_workspace_cleanup(lambda:released.append("workspace"))
            observe_command(1,COMMAND,supervised(),guarded=True,identities=identities())
            verifier._close_invocation_resources([Path("owned-guard")],bad_guard,
                SimpleNamespace(close=lambda:released.append("source")),lambda:None,True,lambda *a,**kw:None)
            return result()
        with self.assertRaisesRegex(InvocationObservationError,"CLEANUP_FAILED"):
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
        self.assertEqual(released,["guard","source","workspace"])
        self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
    def test_nonthrowing_guard_result_errors_also_block_observed_success(self):
        events=[]
        def action():
            defer_workspace_cleanup(lambda:None)
            observe_command(1,COMMAND,supervised(),guarded=True,identities=identities())
            verifier._observe_guarded_cleanup(lambda target:SimpleNamespace(errors=("guard incomplete",),mutations=()),Path("owned"))
            return result()
        with self.assertRaisesRegex(InvocationObservationError,"CLEANUP_FAILED"):
            run_observed(events.append,FINGERPRINT,[COMMAND],action)
        self.assertEqual(events[-1]["status"],"INCOMPLETE_UNKNOWN")
    def test_legacy_guard_cleanup_remains_best_effort_but_releases_other_resources(self):
        released=[]
        def bad_guard(path):raise OSError("legacy guard cleanup fault")
        verifier._close_invocation_resources([Path("owned-guard")],bad_guard,
            SimpleNamespace(close=lambda:released.append("source")),lambda:released.append("workspace"),False,
            lambda *a,**kw:released.append("logged"))
        self.assertEqual(released,["logged","source","workspace"])
    def test_actual_owner_removes_trial_when_source_binding_close_raises(self):
        # Executes the owning Core filesystem/finally path, no npm or source capture.
        class BrokenClose:
            def close(self):raise RuntimeError("injected source binding close")
        for observer in [False,True]:
            with self.subTest(observer=observer),tempfile.TemporaryDirectory() as raw,ExitStack() as patches:
                parent=Path(raw)
                substitutions={"active_source_snapshot":None,"_validate_assignment_materialization":None,
                    "resolve_project_topology":SimpleNamespace(),"configure_prepared_artifact_store":None,
                    "workspace_backend_summary":"engineering-control","prepared_snapshot_storage_root":parent,
                    "storage_summary":"engineering-control","verification_trial_parent":parent,
                    "reap_orphan_verification_trials":None}
                for name,value in substitutions.items():patches.enter_context(patch.object(verifier,name,return_value=value))
                patches.enter_context(patch.object(verifier,"_materialize_workspace",side_effect=RuntimeError("injected early materialization")))
                patches.enter_context(patch.object(verifier.contextlib,"ExitStack",return_value=BrokenClose()))
                config=verifier.BaselineVerifyConfig(attempt_timeout_seconds=5)
                action=lambda:verifier._verify_assignment_uncached_impl(parent,{"demo":"2.0.0"},config=config)
                with self.assertRaisesRegex(RuntimeError,"source binding close"):
                    run_observed(lambda event:None,FINGERPRINT,[COMMAND],action) if observer else action()
                self.assertEqual(list(parent.glob("dependency-flow-baseline-verify-*")),[])

if __name__=="__main__":unittest.main()
