"""Opt-in exact source budgets preserve content proof and legacy semantics."""
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import source_snapshot as core
import cross_process_io


class ExactSourceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'package.json').write_text('{"name":"source-budget-fixture","version":"1.0.0"}',encoding='utf-8')

    def test_fractional_exact_manifest_fails_where_legacy_rounding_keeps_one_second(self):
        original=core._hash_regular_file
        def slow(*a,**kw):
            time.sleep(.35)
            return original(*a,**kw)
        with patch.object(core,'_hash_regular_file',side_effect=slow):
            with self.assertRaisesRegex(core.SourceCaptureError,'SOURCE_MATERIALIZATION_TIMEOUT'):
                core.build_source_tree_manifest(self.root,timeout_seconds=.1,exact_timeout=True)
            legacy=core.build_source_tree_manifest(self.root,timeout_seconds=.1)
        self.assertEqual(legacy.file_count,1)

    def test_complete_exact_manifest_preserves_all_content_entries(self):
        legacy=core.build_source_tree_manifest(self.root,timeout_seconds=5)
        exact=core.build_source_tree_manifest(self.root,timeout_seconds=5.0,exact_timeout=True)
        self.assertEqual(legacy.entries,exact.entries);self.assertEqual(legacy.key,exact.key)

    def test_shared_admission_preserves_fraction_and_rejects_exhaustion(self):
        @contextmanager
        def delayed(*a,**kw):yield 200
        @cross_process_io.coordinated_io('hash',error_type=core.SourceCaptureError)
        def observed(**kwargs):return kwargs['timeout_seconds']
        with patch.object(cross_process_io,'shared_io_slot',delayed):
            self.assertAlmostEqual(observed(timeout_seconds=.25,exact_timeout=True),.05)
            with self.assertRaisesRegex(core.SourceCaptureError,'SOURCE_MATERIALIZATION_TIMEOUT'):
                observed(timeout_seconds=.1,exact_timeout=True)
            self.assertEqual(observed(timeout_seconds=.25),1)

    def test_live_fingerprint_forwards_shared_remaining_to_manifest(self):
        deadline=time.monotonic()+5
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise core.SourceCaptureError('SOURCE_MATERIALIZATION_TIMEOUT')
            return value
        with patch.object(core,'build_source_tree_manifest',wraps=core.build_source_tree_manifest) as manifest:
            key=core.source_snapshot_fingerprint(self.root,remaining_budget=remaining)
        self.assertEqual(len(key),32);self.assertEqual(manifest.call_count,1)
        self.assertTrue(manifest.call_args.kwargs['exact_timeout'])
        self.assertGreater(manifest.call_args.kwargs['timeout_seconds'],0)
        self.assertLessEqual(manifest.call_args.kwargs['timeout_seconds'],5)

    def test_budgeted_live_fingerprint_never_borrows_active_sealed_snapshot(self):
        with patch.object(core,'active_source_snapshot',return_value=object()), \
             patch.object(core,'validate_source_snapshot',side_effect=AssertionError('must read live bytes')):
            key=core.source_snapshot_fingerprint(self.root,remaining_budget=lambda:5.)
        self.assertEqual(len(key),32)

    def test_absent_budget_retains_active_snapshot_legacy_path(self):
        snapshot=object()
        with patch.object(core,'active_source_snapshot',return_value=snapshot), \
             patch.object(core,'validate_source_snapshot',return_value=SimpleNamespace(key='a'*32)) as validate, \
             patch.object(core,'build_source_tree_manifest') as manifest:
            self.assertEqual(core.source_snapshot_fingerprint(self.root),'a'*32)
        validate.assert_called_once_with(snapshot);manifest.assert_not_called()


if __name__=='__main__':unittest.main()
