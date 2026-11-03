import json,copy,time,unittest,importlib.util,os
from pathlib import Path
from resolved_dependency_state import compile_npm_dependency_obligations,npm_root_assignment_from_obligations,MaterializedDependencyObligationError,_canonical_hash
from source_snapshot import source_snapshot_fingerprint
from materialized_workspace_verifier import verify_current_workspace
spec=importlib.util.spec_from_file_location('_root_assignment_fixture',Path(__file__).with_name('test_materialized_workspace_verifier.py'));fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
class DeclaredRootAssignmentTests(unittest.TestCase):
 setUp=fixtures.CurrentWorkspaceVerificationTests.setUp
 def plan_with_hoisted_leaf(self):
  root={'name':'real-shaped-regression','version':'1.0.0','private':True,'dependencies':{'root':'1.0.0'}}
  lock={'lockfileVersion':3,'packages':{'':root,'node_modules/root':{'version':'1.0.0','dependencies':{'leaf':'^1'}},'node_modules/leaf':{'version':'1.0.0'}}};raw=json.dumps(lock).encode();(self.project/'package.json').write_text(json.dumps(root));(self.project/'package-lock.json').write_bytes(raw)
  for name,meta in [('root',{'dependencies':{'leaf':'^1'}}),('leaf',{})]:
   p=self.project/'node_modules'/name;p.mkdir(parents=True);(p/'package.json').write_text(json.dumps({'name':name,'version':'1.0.0',**meta}))
  return compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64)
 @unittest.skipUnless(os.name=='nt','Native guaranteed-tree workspace profile is Windows-only')
 def test_hoisted_transitive_is_not_declared_root_but_stays_physical_obligation(self):
  plan=self.plan_with_hoisted_leaf();self.assertEqual(npm_root_assignment_from_obligations(plan),{'root':'1.0.0'});self.assertEqual(len(plan['instances']),2)
  result=verify_current_workspace(self.project,expected_source_key=source_snapshot_fingerprint(self.project),dependency_plan=plan,commands=[fixtures.command("console.log('actual root and hoisted leaf');")],cache_dir=self.cache,deadline=time.time()+45,final_profile_digest='c'*64)
  self.assertEqual(result['materializedDependencyObligations']['instanceCount'],2);self.assertEqual(result['materializedDependencyObligations']['unknownCount'],0);self.assertEqual(len(result['commandObservations']),1);self.assertFalse(result['fullAcceptance'])
 def test_missing_declared_root_not_dropped_and_tampered_plan_not_accepted(self):
  plan=self.plan_with_hoisted_leaf();plan['instances']=[r for r in plan['instances'] if r['installName']!='root'];plan['obligationPlanDigest']=_canonical_hash({k:v for k,v in plan.items() if k!='obligationPlanDigest'})
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'DECLARED_ROOT_INSTANCE'):npm_root_assignment_from_obligations(plan)
  plan['rootDeclarations']['dependencies']['foreign']='1.0.0'
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'PLAN_UNPROVEN'):npm_root_assignment_from_obligations(plan)
if __name__=='__main__':unittest.main()
