"""Standalone output closure and real native verifier regression boundaries.

Synthetic fixture output is not evidence that a project's TAP tests passed.
The native tests exercise the production source/verifier/command boundary.
"""
import hashlib,json,os,shutil,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from standalone_build_outputs import (PROFILE,KIND,GeneratedOutputError,validate_spec,
    require_absent,output_inventory,capture_receipt,receipt_current)
from source_snapshot import SourceInputPolicy,SourceCaptureError,source_snapshot_fingerprint
from scoped_source_policy import policy_from_payload,policy_payload
from verification_source_closure import require_complete_source_policy

UUID='00000000-0000-4000-8000-000000000001.json'
H=lambda raw:hashlib.sha256(raw).hexdigest()
class _Fixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.project=self.root/'project';self.project.mkdir()
        self.cache=self.root/'cache';self.cache.mkdir()
        self.env=patch.dict(os.environ,{'GIT_CEILING_DIRECTORIES':str(self.root),'NODE_OPTIONS':'','NODE_PATH':'','DEPLOOM_SOURCE_SCOPE_MODE':PROFILE})
        self.env.start();self.addCleanup(self.env.stop)
        for d in ['scripts','tests']:(self.project/d).mkdir()
        self.files=['dist/config.cjs','dist/config.d.ts','dist/index.cjs','dist/index.d.ts']
        self.body="const fs=require('fs');fs.mkdirSync('dist');for(const n of ['config.cjs','config.d.ts','index.cjs','index.d.ts'])fs.writeFileSync('dist/'+n,'built');fs.mkdirSync('.tap/processinfo',{recursive:true});fs.mkdirSync('.tap/test-results/tests',{recursive:true});fs.writeFileSync('.tap/processinfo/"+UUID+"','{}');fs.writeFileSync('.tap/test-results/tests/a.js.tap','ok 1\\n');"
        (self.project/'scripts/build.js').write_text(self.body)
        (self.project/'tests/a.js').write_text('// synthetic input\n')
        self.package={'name':'typed-output-fixture','version':'1.0.0','private':True,'scripts':{
            'test':'node scripts/build.js','test:perf':'node -e "process.exit(0)"'}}
        self.writepackage()
        lock={'name':self.package['name'],'version':'1.0.0','lockfileVersion':2,'requires':True,'packages':{'':{'name':self.package['name'],'version':'1.0.0'}}}
        self.lock=json.dumps(lock).encode();(self.project/'package-lock.json').write_bytes(self.lock)
        self.commands=['npm test','npm run test:perf'];self.spec=self.makespec()
        self.binding={'sourceSnapshotKey':'s','profileDigest':'p','invocationId':'i','dependencyPlanDigest':'d','approvedLockSha256':'l','environmentDigest':'e','toolchain':{},'buildCommandDigest':'c'}
    def writepackage(self):(self.project/'package.json').write_text(json.dumps(self.package))
    def makespec(self):
        return {'schemaVersion':1,'kind':KIND,'buildFiles':self.files,'testFiles':['tests/a.js'],'emptyDirectories':[],
            'buildScriptSha256':H((self.project/'scripts/build.js').read_bytes()),
            'testScriptSha256':H(self.package['scripts']['test'].encode()),'perfScriptSha256':H(self.package['scripts']['test:perf'].encode())}
    def outputs(self):
        for name in self.files+['.tap/processinfo/'+UUID,'.tap/test-results/tests/a.js.tap']:
            p=self.project/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
    def receipt(self):return capture_receipt(self.project,self.spec,deadline=time.time()+10,binding=self.binding)

class OutputContractTests(_Fixture):
    def test_policy_roundtrip_default_unchanged(self):
        self.assertEqual(policy_payload(SourceInputPolicy()),{})
        typed=policy_from_payload({'mode':PROFILE});self.assertEqual(typed.generated_output_profile,PROFILE)
        self.assertEqual(policy_payload(typed),{'mode':PROFILE})
        self.assertEqual(typed.excluded_path_set,frozenset(('dist','.tap')))
        self.assertNotEqual(typed.key,SourceInputPolicy().key)
        with self.assertRaises(SourceCaptureError):policy_from_payload({'mode':PROFILE,'excludedPaths':['tests']})
    def test_generic_complete_proof_cannot_accept_receiptless_exclusions(self):
        with self.assertRaisesRegex(SourceCaptureError,'GENERATED_OUTPUT_RECEIPT_REQUIRED'):
            require_complete_source_policy(SourceInputPolicy(generated_output_profile=PROFILE))
        self.assertEqual(require_complete_source_policy(SourceInputPolicy())['strategy'],'conservative-authoritative-root')
    def test_source_input_policy_retains_authored_inputs(self):
        before=source_snapshot_fingerprint(self.project);self.outputs()
        self.assertEqual(source_snapshot_fingerprint(self.project),before)
        (self.project/'scripts/build.js').write_text('changed')
        self.assertNotEqual(source_snapshot_fingerprint(self.project),before)
    def test_durable_source_policy_reopens_without_copying_derived_outputs(self):
        from source_snapshot import capture_durable_source_snapshot,open_source_snapshot
        self.outputs()
        captured=capture_durable_source_snapshot(self.project,self.root/'durable',timeout_seconds=15)
        reopened=open_source_snapshot(captured.container,expected_key=captured.key,timeout_seconds=15)
        self.assertEqual(reopened.input_policy.generated_output_profile,PROFILE)
        self.assertFalse((reopened.project_path/'dist').exists())
        self.assertFalse((reopened.project_path/'.tap').exists())
        self.assertEqual((reopened.project_path/'scripts/build.js').read_bytes(),(self.project/'scripts/build.js').read_bytes())
    def test_fresh_roots_required(self):
        require_absent(self.project,deadline=time.time()+5);(self.project/'.tap').mkdir()
        with self.assertRaisesRegex(GeneratedOutputError,'PREEXISTING_ROOT'):require_absent(self.project,deadline=time.time()+5)
    def test_exact_recipe_and_test_set(self):
        validate_spec(self.spec,self.project,self.commands)
        with self.assertRaisesRegex(GeneratedOutputError,'COMMAND_RECIPE'):validate_spec(self.spec,self.project,['npm test','npm test'])
        (self.project/'tests/other.js').write_text('')
        with self.assertRaisesRegex(GeneratedOutputError,'TEST_SET'):validate_spec(self.spec,self.project,self.commands)
    def test_byte_tamper_delete_or_binding_change_not_current(self):
        self.outputs();r=self.receipt();self.assertTrue(receipt_current(self.project,self.spec,r,deadline=time.time()+5,binding=self.binding))
        self.assertFalse(receipt_current(self.project,self.spec,r,deadline=time.time()+5,binding={}))
        (self.project/'dist/index.cjs').write_text('tampered')
        self.assertFalse(receipt_current(self.project,self.spec,r,deadline=time.time()+5,binding=self.binding))
        (self.project/'dist/index.cjs').unlink()
        self.assertFalse(receipt_current(self.project,self.spec,r,deadline=time.time()+5,binding=self.binding))
    def test_unknown_file_or_directory_rejected(self):
        self.outputs();extra=self.project/'.tap/hidden';extra.mkdir()
        with self.assertRaisesRegex(GeneratedOutputError,'UNEXPECTED_DIRECTORY'):self.receipt()
        extra.rmdir();(self.project/'dist/hidden.js').write_text('')
        with self.assertRaisesRegex(GeneratedOutputError,'UNEXPECTED_FILE'):self.receipt()
    def test_missing_test_result_is_not_covered_by_process_count(self):
        self.outputs();(self.project/'.tap/test-results/tests/a.js.tap').unlink()
        with self.assertRaisesRegex(GeneratedOutputError,'MISSING_FILES'):self.receipt()
    def test_uuid_scope_and_count_cap(self):
        self.outputs();(self.project/'.tap/processinfo/wrong.json').write_text('{}')
        with self.assertRaisesRegex(GeneratedOutputError,'UNEXPECTED_FILE'):self.receipt()
    def test_only_explicit_empty_fixture_directory_may_be_observed(self):
        self.outputs();directory=self.project/'.tap/fixtures';directory.mkdir()
        with self.assertRaisesRegex(GeneratedOutputError,'UNEXPECTED_DIRECTORY'):self.receipt()
        self.spec['emptyDirectories']=['.tap/fixtures'];self.receipt()
        (directory/'leftover').write_text('fixture payload')
        with self.assertRaisesRegex(GeneratedOutputError,'FIXTURE_CLEANUP_INCOMPLETE'):self.receipt()
    def test_hardlink_rejected_without_reading_external_content(self):
        self.outputs();target=self.project/'dist/index.cjs';target.unlink();os.link(self.project/'tests/a.js',target)
        with self.assertRaisesRegex(GeneratedOutputError,'LINK_OR_TYPE'):self.receipt()
    def test_process_count_cap_is_not_automatically_extended(self):
        self.outputs()
        for i in range(129):
            (self.project/('.tap/processinfo/%08x-0000-4000-8000-000000000002.json'%i)).write_text('{}')
        with self.assertRaisesRegex(GeneratedOutputError,'SIZE_OR_COUNT_CAP'):self.receipt()
    def test_oversized_file_rejected_before_hash(self):
        self.outputs()
        with (self.project/'dist/index.cjs').open('wb') as f:f.truncate(8*1024*1024+1)
        with self.assertRaisesRegex(GeneratedOutputError,'SIZE_CAP'):self.receipt()
    @unittest.skipUnless(os.name=='nt','NTFS junction regression')
    def test_real_junction_is_rejected(self):
        import subprocess
        self.outputs();target=self.project/'dist';backup=self.project/'saved-dist';target.rename(backup)
        result=subprocess.run(['cmd.exe','/c','mklink','/J',str(target),str(backup)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        try:
            with self.assertRaisesRegex(GeneratedOutputError,'LINK_OR_TYPE'):self.receipt()
        finally:os.rmdir(target)
    def test_expired_capture_is_not_missing_incompatibility(self):
        self.outputs()
        with self.assertRaisesRegex(GeneratedOutputError,'DEADLINE'):capture_receipt(self.project,self.spec,deadline=time.time()-1,binding=self.binding)

@unittest.skipUnless(os.name=='nt' and shutil.which('node'),'Windows guaranteed-tree output profile required')
class NativeOutputBoundaryTests(_Fixture):
    def invoke(self,*,spec=True):
        from materialized_workspace_verifier import verify_current_workspace
        from resolved_dependency_state import compile_npm_dependency_obligations
        plan=compile_npm_dependency_obligations(self.lock,self.lock,exact_targets={},changed_instances=[],immutable_packages=[],excluded_packages=[],delta_digest='a'*64,scope_digest='b'*64)
        return verify_current_workspace(self.project,expected_source_key=source_snapshot_fingerprint(self.project),dependency_plan=plan,
            commands=self.commands,cache_dir=self.cache,final_profile_digest='c'*64,deadline=time.time()+45,
            generated_output_spec=self.spec if spec else None)
    def test_native_original_commands_create_bound_receipt(self):
        value=self.invoke();r=value['generatedOutputObservation']
        self.assertEqual(len([x for x in r['inventory'] if x['type']=='file']),6)
        self.assertEqual(r['binding']['sourceSnapshotKey'],value['sourceSnapshotKey'])
        self.assertEqual(r['binding']['dependencyPlanDigest'],value['materializedDependencyObligations']['obligationPlanDigest'])
        self.assertTrue(all(x['descendantsRemaining']==0 for x in value['ownerOperationObservations']))
        self.assertFalse(value['fullAcceptance']);self.assertFalse(value['checkpointPublished'])
    def test_native_receiptless_policy_stops_before_commands(self):
        from materialized_workspace_verifier import MaterializedWorkspaceVerificationError
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'OUTPUT_CONTRACT_REQUIRED') as e:self.invoke(spec=False)
        self.assertEqual(e.exception.operation_observations,())
    def test_native_preexisting_outputs_reject_before_commands(self):
        self.outputs()
        with self.assertRaisesRegex(GeneratedOutputError,'PREEXISTING_ROOT'):self.invoke()
    def test_native_second_command_cannot_mutate_outputs(self):
        from materialized_workspace_verifier import MaterializedWorkspaceVerificationError
        self.package['scripts']['test:perf']='node -e "require(\'fs\').writeFileSync(\'dist/index.cjs\',\'changed\')"'
        self.writepackage();self.spec=self.makespec()
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'OUTPUT_CHANGED'):self.invoke()
    def test_native_first_command_cannot_mutate_authored_input(self):
        from materialized_workspace_verifier import MaterializedWorkspaceVerificationError
        (self.project/'scripts/build.js').write_text(self.body+"require('fs').writeFileSync('tests/a.js','changed');")
        self.spec=self.makespec()
        with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'INPUT_CHANGED'):self.invoke()

if __name__=='__main__':unittest.main()
