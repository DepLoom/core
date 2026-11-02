"""Real filesystem transport tests. A copied tree is never verification evidence."""
import copy,dataclasses,time,unittest
from unittest.mock import patch
from pathlib import Path
from test_standalone_build_outputs import _Fixture
import source_snapshot as core
from standalone_build_outputs import PROFILE,GeneratedOutputError,validate_input_only_materialization
from verification_source_closure import require_complete_source_policy

class TypedSourceTransportTests(_Fixture):
    def contract(self):return {'spec':self.spec,'commands':self.commands}
    def test_legacy_generic_transport_still_rejects_typed_exclusions(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True):
            with self.assertRaisesRegex(core.SourceCaptureError,'GENERATED_OUTPUT_RECEIPT_REQUIRED'):
                core.materialize_source_for_verification(self.project,self.root/'copy',timeout_seconds=10)
        self.assertFalse((self.root/'copy').exists())
    def test_real_typed_copy_retains_authored_inputs_but_grants_no_proof(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
            project,used,method=core.materialize_source_for_verification(self.project,self.root/'copy',timeout_seconds=10,generated_output_materialization=self.contract())
            self.assertEqual(used.key,snapshot.key)
            self.assertEqual((project/'package.json').read_bytes(),(self.project/'package.json').read_bytes())
            self.assertEqual((project/'scripts/build.js').read_bytes(),(self.project/'scripts/build.js').read_bytes())
            self.assertFalse((project/'dist').exists());self.assertFalse((project/'.tap').exists())
            with self.assertRaisesRegex(core.SourceCaptureError,'GENERATED_OUTPUT_RECEIPT_REQUIRED'):require_complete_source_policy(used.input_policy)
    def test_original_existing_output_root_is_not_silently_dropped(self):
        (self.project/'dist').mkdir()
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True):
            with self.assertRaisesRegex(GeneratedOutputError,'PREEXISTING_ROOT'):
                core.materialize_source_for_verification(self.project,self.root/'copy',timeout_seconds=10,generated_output_materialization=self.contract())
        self.assertFalse((self.root/'copy').exists())
    def test_wrong_recipe_and_extra_contract_keys_reject(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
            bad=copy.deepcopy(self.contract());bad['spec']['testScriptSha256']='0'*64
            with self.assertRaisesRegex(GeneratedOutputError,'SOURCE_RECIPE'):validate_input_only_materialization(snapshot,self.project,bad,deadline=time.time()+10)
            with self.assertRaisesRegex(core.SourceCaptureError,'TRANSPORT_CONTRACT_INVALID'):validate_input_only_materialization(snapshot,self.project,{**self.contract(),'verified':True},deadline=time.time()+10)
    def test_other_source_exclusions_or_wrong_origin_reject(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
            wrong=dataclasses.replace(snapshot,input_policy=core.SourceInputPolicy())
            with self.assertRaisesRegex(core.SourceCaptureError,'TRANSPORT_CONTRACT_INVALID'):validate_input_only_materialization(wrong,self.project,self.contract(),deadline=time.time()+10)
            wrong=dataclasses.replace(snapshot,original_project_path=self.root/'foreign')
            with self.assertRaisesRegex(core.SourceCaptureError,'TRANSPORT_CONTRACT_INVALID'):validate_input_only_materialization(wrong,self.project,self.contract(),deadline=time.time()+10)
    def test_live_output_root_appearing_during_copy_rejects(self):
        actual=core.materialize_private_tree
        def copy_then_mutate(*args,**kwargs):
            result=actual(*args,**kwargs);(self.project/'.tap').mkdir();return result
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True):
            with patch.object(core,'materialize_private_tree',side_effect=copy_then_mutate):
                with self.assertRaisesRegex(GeneratedOutputError,'PREEXISTING_ROOT'):
                    core.materialize_source_for_verification(self.project,self.root/'copy',timeout_seconds=10,generated_output_materialization=self.contract())
    def test_delivered_recipe_or_output_is_not_accepted(self):
        with core.verification_source_snapshot_scope(self.project,timeout_seconds=10,strict_cleanup=True) as snapshot:
            target=self.root/'copy'
            import shutil
            shutil.copytree(self.project,target);(target/'dist').mkdir()
            with self.assertRaisesRegex(GeneratedOutputError,'PREEXISTING_ROOT'):validate_input_only_materialization(snapshot,self.project,self.contract(),deadline=time.time()+10,delivered_project=target)

if __name__=='__main__':unittest.main()
