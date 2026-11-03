"""Orphan maintenance never supplies proof and may leave a critical path."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import source_snapshot as core


class SnapshotMaintenanceDeferralTests(unittest.TestCase):
    def test_deferred_reaper_performs_no_candidate_discovery(self):
        import source_snapshot_storage as storage
        with patch.object(storage,'candidate_snapshot_parents',side_effect=AssertionError('must not inspect old roots')):
            with core.defer_orphan_snapshot_maintenance():
                self.assertEqual(core.reap_orphaned_source_snapshots(),{'reaped':0,'skipped':0,'failed':0})

    def test_deferral_does_not_consume_later_first_reap(self):
        event=threading.Event()
        with patch.object(core,'_REAP_DONE',event),patch.object(core,'reap_orphaned_source_snapshots') as reap:
            with core.defer_orphan_snapshot_maintenance():core._reap_once()
            self.assertFalse(event.is_set());reap.assert_not_called()
            core._reap_once();reap.assert_called_once_with();self.assertTrue(event.is_set())
            core._reap_once();self.assertEqual(reap.call_count,1)

    def test_nested_deferral_and_exception_restore_context(self):
        self.assertFalse(core._ORPHAN_REAP_DEFERRED.get())
        with self.assertRaisesRegex(RuntimeError,'test'):
            with core.defer_orphan_snapshot_maintenance():
                with core.defer_orphan_snapshot_maintenance():self.assertTrue(core._ORPHAN_REAP_DEFERRED.get())
                self.assertTrue(core._ORPHAN_REAP_DEFERRED.get());raise RuntimeError('test')
        self.assertFalse(core._ORPHAN_REAP_DEFERRED.get())

    def test_deferral_is_not_a_global_disable_for_other_threads(self):
        seen=[]
        with core.defer_orphan_snapshot_maintenance():
            thread=threading.Thread(target=lambda:seen.append(core._ORPHAN_REAP_DEFERRED.get()))
            thread.start();thread.join(2);self.assertFalse(thread.is_alive())
            self.assertTrue(core._ORPHAN_REAP_DEFERRED.get())
        self.assertEqual(seen,[False])

    def test_real_capture_keeps_complete_integrity_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);project=base/'project';project.mkdir();target=base/'sealed'
            (project/'package.json').write_text('{"name":"maintenance-native-fixture","version":"1.0.0"}',encoding='utf-8')
            (project/'index.js').write_text('module.exports = 1;\n',encoding='utf-8')
            try:
                original_reap=core.reap_orphaned_source_snapshots
                def deferred_reap(*args,**kwargs):
                    self.assertTrue(core._ORPHAN_REAP_DEFERRED.get())
                    return original_reap(*args,**kwargs)
                with patch.object(core,'reap_orphaned_source_snapshots',side_effect=deferred_reap):
                    with core.defer_orphan_snapshot_maintenance():
                        snapshot=core.capture_durable_source_snapshot(project,target,timeout_seconds=15)
                opened=core.open_source_snapshot(target,expected_key=snapshot.key,timeout_seconds=10)
                self.assertEqual(opened.key,snapshot.key);self.assertEqual(opened.file_count,2)
                self.assertFalse(core._ORPHAN_REAP_DEFERRED.get())
                (project/'index.js').write_text('module.exports = 2;\n',encoding='utf-8')
                self.assertEqual(core.open_source_snapshot(target,expected_key=snapshot.key,timeout_seconds=10).key,snapshot.key)
                core._apply_tree_write_protection(target/'tree',readonly=False)
                (target/'tree/index.js').write_text('tampered\n',encoding='utf-8')
                with self.assertRaisesRegex(core.SourceCaptureError,'SOURCE_SNAPSHOT_CONTENT_MISMATCH'):
                    core.open_source_snapshot(target,expected_key=snapshot.key,timeout_seconds=10)
            finally:
                self.assertTrue(target.resolve().is_relative_to(base.resolve()))
                core._force_rmtree(target)


if __name__=='__main__':unittest.main()
