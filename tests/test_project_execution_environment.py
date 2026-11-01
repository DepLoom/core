"""Controlled env maps + actual supervised Node child, without package manager."""
import json,os,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from project_execution_environment import (LEGACY,V2,ProjectExecutionEnvironmentError,
    project_execution_environment,workspace_execution_environment,project_environment_fingerprint,project_environment_observation)

class ProjectEnvironmentTests(unittest.TestCase):
 def host(self,**extra):return {'PATH':'known-path','CI':'1','CODEX_TOOL_CALL_ID':'transport-A',**extra}
 def build(self,host):return project_execution_environment(host,contract=V2)
 def test_only_transport_id_is_removed_from_actual_mapping(self):
  before=self.host(CODEX_OTHER='preserved');env=self.build(before)
  self.assertNotIn('CODEX_TOOL_CALL_ID',env);self.assertEqual(env['CODEX_OTHER'],'preserved');self.assertEqual(before['CODEX_TOOL_CALL_ID'],'transport-A')
  with self.assertRaises(TypeError):env['PATH']='changed'
 def test_v2_call_id_changes_do_not_change_effective_mapping_or_fingerprint(self):
  a=self.build(self.host());b=self.build(self.host(CODEX_TOOL_CALL_ID='transport-B'))
  self.assertEqual(dict(a),dict(b));self.assertEqual(project_environment_fingerprint(a,contract=V2),project_environment_fingerprint(b,contract=V2))
 def test_all_other_semantic_and_codex_values_are_identity_bearing(self):
  a=self.build(self.host());sha=project_environment_fingerprint(a,contract=V2)
  for key in ['PATH','NODE_OPTIONS','NODE_PATH','CI','npm_config_registry','HTTPS_PROXY','npm_config_cache','CODEX_OTHER']:
   with self.subTest(key=key):self.assertNotEqual(sha,project_environment_fingerprint(self.build(self.host(**{key:'different'})),contract=V2))
 def test_missing_and_empty_are_distinct(self):
  a=self.build(self.host());b=self.build(self.host(NODE_PATH=''))
  self.assertNotEqual(project_environment_fingerprint(a,contract=V2),project_environment_fingerprint(b,contract=V2))
 def test_transport_forwarding_cannot_be_hidden_by_fingerprint(self):
  with self.assertRaisesRegex(ProjectExecutionEnvironmentError,'TRANSPORT_ENVIRONMENT_FORWARDED'):
   project_environment_fingerprint(self.host(),contract=V2)
 def test_case_collisions_fail_closed_before_launch(self):
  with self.assertRaisesRegex(ProjectExecutionEnvironmentError,'CASE_COLLISION'):
   project_execution_environment({'PATH':'a','Path':'b'},contract=V2,windows=True)
 def test_windows_normalization_and_explicit_override_are_unambiguous(self):
  env=project_execution_environment({'Path':'a','codex_tool_call_id':'x'},contract=V2,overrides={'PATH':'b'},windows=True)
  self.assertEqual(dict(env),{'PATH':'b'})
 def test_posix_representation_does_not_ignore_other_case_names(self):
  env=project_execution_environment({'CODEX_TOOL_CALL_ID':'x','codex_tool_call_id':'y'},contract=V2,windows=False)
  self.assertEqual(dict(env),{'codex_tool_call_id':'y'})
 def test_invalid_contract_and_invalid_entry_fail_closed(self):
  for env in [{'A=BAD':'x'},{'A':'x\x00y'},{'A':None}]:
   with self.subTest(env=env),self.assertRaises(ProjectExecutionEnvironmentError):self.build(env)
  with self.assertRaises(ProjectExecutionEnvironmentError):project_execution_environment({},contract='UNKNOWN')
 def test_legacy_still_hashes_transport_and_is_not_v2(self):
  from verification_proof import environment_snapshot_fingerprint
  a=project_execution_environment(self.host(),contract=LEGACY)
  self.assertEqual(project_environment_fingerprint(a,contract=LEGACY),environment_snapshot_fingerprint(a))
  self.assertIsNone(project_environment_observation(a,contract=LEGACY))
  self.assertNotEqual(environment_snapshot_fingerprint(a),environment_snapshot_fingerprint(self.host(CODEX_TOOL_CALL_ID='other')))
 def test_v2_receipt_records_actual_mapping_not_caller_claim(self):
  env=self.build(self.host());row=project_environment_observation(env,contract=V2)
  self.assertEqual(row['schemaVersion'],2);self.assertEqual(row['environmentDigest'],project_environment_fingerprint(env,contract=V2));self.assertFalse(row['transportValueForwarded'])

@unittest.skipUnless(os.name=='nt','v2 execution boundary currently local Windows only')
class RealNodeEnvironmentTests(unittest.TestCase):
 def test_actual_child_grandchild_and_native_job_closure_without_transport_id(self):
  from verification_process_supervisor import run_supervised
  before=dict(os.environ);host={**before,'CODEX_TOOL_CALL_ID':'synthetic-transport','DEPLOOM_ENV_PROBE':'semantic-preserved'}
  env=project_execution_environment(host,contract=V2)
  code="const a=require('node:assert/strict'),c=require('node:child_process');a.equal(process.env.CODEX_TOOL_CALL_ID,undefined);a.equal(process.env.DEPLOOM_ENV_PROBE,'semantic-preserved');const r=c.spawnSync(process.execPath,['-e',`if(process.env.CODEX_TOOL_CALL_ID!==undefined)process.exit(41)`],{env:process.env});a.equal(r.status,0);console.log('EXPLICIT_PROJECT_ENV_CHILD_GRANDCHILD_PASS')"
  with tempfile.TemporaryDirectory() as d:r=run_supervised([shutil.which('node'),'-e',code],Path(d),base_env=env,timeout_seconds=10)
  self.assertEqual(r.returncode,0,r.stdout);self.assertEqual(r.supervision.quality,'guaranteed-tree');self.assertEqual(r.supervision.descendants_remaining,0);self.assertEqual(dict(os.environ),before)
 def test_negative_actual_child_detects_legacy_transport_inheritance(self):
  from verification_process_supervisor import run_supervised
  env={**os.environ,'CODEX_TOOL_CALL_ID':'synthetic-transport'}
  with tempfile.TemporaryDirectory() as d:r=run_supervised([shutil.which('node'),'-e',"if(process.env.CODEX_TOOL_CALL_ID!==undefined)process.exit(41)"],Path(d),base_env=env,timeout_seconds=10)
  self.assertEqual(r.returncode,41);self.assertEqual(r.supervision.descendants_remaining,0)
 def test_actual_timeout_is_owned_without_transport_id(self):
  from verification_process_supervisor import run_supervised
  env=project_execution_environment({**os.environ,'CODEX_TOOL_CALL_ID':'synthetic-transport'},contract=V2)
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(subprocess.TimeoutExpired) as caught:run_supervised([shutil.which('node'),'-e','setInterval(()=>{},1000)'],Path(d),base_env=env,timeout_seconds=1)
  self.assertEqual(caught.exception.supervision.quality,'guaranteed-tree');self.assertEqual(caught.exception.supervision.descendants_remaining,0)

@unittest.skipUnless(os.name=='nt','v2 actual owner is local Windows only')
class ActualWorkspaceEnvironmentBoundaryTests(unittest.TestCase):
 def test_actual_current_owner_passes_explicit_env_without_install_or_project_migration(self):
  from unittest.mock import patch
  from materialized_workspace_verifier import verify_current_workspace,MaterializedWorkspaceVerificationError
  from resolved_dependency_state import compile_npm_dependency_obligations
  from source_snapshot import source_snapshot_fingerprint
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);project=root/'project';project.mkdir();cache=root/'cache';cache.mkdir();(project/'node_modules').mkdir()
   manifest={'name':'empty-environment-diagnostic','version':'1.0.0','private':True}
   lock={'name':manifest['name'],'version':'1.0.0','lockfileVersion':2,'requires':True,'packages':{'':manifest}}
   (project/'package.json').write_text(json.dumps(manifest));raw=json.dumps(lock).encode();(project/'package-lock.json').write_bytes(raw)
   plan=compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],immutable_packages=[],excluded_packages=[],delta_digest='a'*64,scope_digest='b'*64)
   with patch.dict(os.environ,{'GIT_CEILING_DIRECTORIES':str(root),'NODE_OPTIONS':'','NODE_PATH':''}):
    key=source_snapshot_fingerprint(project);host={**os.environ,'CODEX_TOOL_CALL_ID':'synthetic-transport'}
    command='node -e '+json.dumps("if(process.env.CODEX_TOOL_CALL_ID!==undefined)process.exit(41);console.log('ACTUAL_OWNER_TRANSPORT_ABSENT')")
    result=verify_current_workspace(project,expected_source_key=key,dependency_plan=plan,commands=[command],cache_dir=cache,deadline=time.time()+30,final_profile_digest='c'*64,environment=host,materialize=False,environment_contract=V2)
    self.assertEqual(result['environmentDigest'],result['projectExecutionEnvironment']['environmentDigest'])
    self.assertEqual(result['projectExecutionEnvironment']['schemaVersion'],2)
    self.assertEqual(len(result['ownerOperationObservations']),1);self.assertEqual(result['ownerOperationObservations'][0]['operation'],'project-command')
    self.assertEqual(result['installation']['status'],'EXISTING_TREE_PHYSICALLY_OBSERVED')
    self.assertTrue(result['ownedCleanupConfirmed']);self.assertFalse(result['currentWorkspaceVerified'])
    with self.assertRaisesRegex(MaterializedWorkspaceVerificationError,'COMMAND_FAILED'):
     verify_current_workspace(project,expected_source_key=key,dependency_plan=plan,commands=[command],cache_dir=cache,deadline=time.time()+30,final_profile_digest='c'*64,environment=host,materialize=False,environment_contract=LEGACY)
 def test_tool_identity_changes_when_environment_or_actual_workspace_owner_changes(self):
  import substrate_identity
  from unittest.mock import patch
  clear=lambda:(substrate_identity.tool_build_components.cache_clear(),substrate_identity.tool_build_id.cache_clear())
  clear();self.addCleanup(clear);original=substrate_identity._file_digest;baseline=substrate_identity.tool_build_id()
  for name in ['project_execution_environment.py','materialized_workspace_verifier.py']:
   clear()
   with patch.object(substrate_identity,'_file_digest',side_effect=lambda p:'changed-owner' if p.name==name else original(p)):
    with self.subTest(name=name):self.assertNotEqual(baseline,substrate_identity.tool_build_id())
   clear()

if __name__=='__main__':unittest.main()
