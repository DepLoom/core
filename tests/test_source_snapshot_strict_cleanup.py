"""Owned SourceSnapshot strict retirement must fail on silent filesystem cleanup failure."""
from pathlib import Path
import os,shutil,subprocess,tempfile,unittest
from unittest.mock import patch
import source_snapshot as core

class StrictSnapshotCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.project=Path(self.temp.name)/'fixture';self.project.mkdir()
        self.storage=Path(self.temp.name)/'verification'
        environment=patch.dict(os.environ,{'DEPLOOM_VERIFICATION_ROOT':str(self.storage),'DEPLOOM_VEX_AUTO_REFS':'0'})
        environment.start();self.addCleanup(environment.stop)
        (self.project/'package.json').write_text('{"name":"engineering-source","version":"1.0.0"}\n')
        for args in [['init','-q'],['add','--','package.json'],['-c','user.name=DepLoom Engineering Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgSign=false','commit','-q','-m','engineering fixture']]:
            subprocess.run([shutil.which('git'),'-C',str(self.project),*args],capture_output=True,check=True,timeout=5)
    def cleanup_owned(self,snapshot):
        root=Path(os.environ['DEPLOOM_VERIFICATION_ROOT']).resolve()
        self.assertTrue(snapshot.container.resolve().is_relative_to(root))
        self.assertTrue(snapshot.container.name.startswith('dependency-flow-source-snapshot-'))
        core._force_rmtree(snapshot.container)
        self.assertFalse(snapshot.container.exists())
    def test_strict_scope_confirms_container_is_removed(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
            self.assertTrue(snapshot.container.exists())
        self.assertFalse(snapshot.container.exists())
    def test_silent_retirement_failure_is_rejected_in_strict_scope(self):
        scope=core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True);snapshot=scope.__enter__()
        try:
            with patch.object(core,'_force_rmtree',return_value=None),self.assertRaisesRegex(core.SourceCaptureError,'SOURCE_SNAPSHOT_CLEANUP_INCOMPLETE'):
                scope.__exit__(None,None,None)
            self.assertTrue(snapshot.container.exists())
        finally:self.cleanup_owned(snapshot)
    def test_default_legacy_scope_stays_best_effort(self):
        scope=core.verification_source_snapshot_scope(self.project,timeout_seconds=10);snapshot=scope.__enter__()
        try:
            with patch.object(core,'_force_rmtree',return_value=None):scope.__exit__(None,None,None)
            self.assertTrue(snapshot.container.exists())
        finally:self.cleanup_owned(snapshot)
    def test_primary_failure_is_preserved_and_cleanup_failure_noted(self):
        original=RuntimeError('primary engineering failure');snapshot=None
        try:
            with self.assertRaises(RuntimeError) as caught:
                with patch.object(core,'_force_rmtree',return_value=None):
                    with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
                        raise original
            self.assertIs(caught.exception,original)
            self.assertIn('SOURCE_SNAPSHOT_CLEANUP_INCOMPLETE',original.__notes__)
        finally:
            if snapshot and snapshot.container.exists():self.cleanup_owned(snapshot)
    def test_strict_scope_cannot_claim_shared_caller_snapshot_ownership(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10):
            with self.assertRaisesRegex(core.SourceCaptureError,'STRICT_SCOPE_OWNERSHIP_REQUIRED'):
                with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True):pass
    def test_throwing_retirement_preserves_primary_failure_in_strict_scope(self):
        original=RuntimeError('primary engineering failure');snapshot=None
        try:
            with self.assertRaises(RuntimeError) as caught:
                with patch.object(core,'_retire_completed_request',side_effect=OSError('engineering retirement throw')):
                    with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
                        raise original
            self.assertIs(caught.exception,original)
            self.assertIn('SOURCE_SNAPSHOT_RETIREMENT_FAILED: OSError',original.__notes__)
        finally:
            if snapshot is not None:
                core._retire_completed_request(snapshot)
                self.cleanup_owned(snapshot)

    def test_watcher_retirement_error_rejects_even_when_container_removed(self):
        from types import SimpleNamespace
        snapshot=None
        with self.assertRaisesRegex(core.SourceCaptureError,'SOURCE_SNAPSHOT_CLEANUP_INCOMPLETE'):
            with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
                # Negative resource-control double alongside actual Core capture.
                with core._LOCK:
                    core._ACTIVE_WATCHERS['engineering-retirement-fault-'+snapshot.key]=(snapshot,
                        SimpleNamespace(stop=lambda:None,errors=['engineering watcher stop failed'],_thread=None))
        self.assertFalse(snapshot.container.exists())

    def test_strict_scope_refuses_completed_request_reuse(self):
        with self.assertRaisesRegex(core.SourceCaptureError,'STRICT_SCOPE_OWNERSHIP_REQUIRED'):
            with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True,reuse_completed=True):pass

if __name__=='__main__':unittest.main()
