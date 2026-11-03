"""Publication invariants for incomplete Drafts; no live network."""
from __future__ import annotations
import dataclasses,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import dependency_live_roadmap_generator as core


def row(name='sample',target='2.0.0',current='1.0.0'):
 return core.DependencyRow(project='fixture',package_dir='.',name=name,kind='dev',requested_spec=current,current_version=current,current_source='package-lock.json',latest_version='3.0.0',current_vulns='0',min_no_critical=current,min_no_high=current,min_no_vuln=current,min_lag_12m='2.0.0',min_lag_9m='2.0.0',min_lag_6m='2.0.0',min_lag_3m='2.0.0',group=1,reason='observed candidate',notes='',target_default=target,target_yellow=target,target_green=target,draft_scan_state='done')

class PartialOwnerContractTests(unittest.TestCase):
 def publish(self,rows,intent,status='DRAFT_READY',**kwargs):
  self.addCleanup(setattr,core,'_ARTIFACTS_BASE_FOR_DRAFT',list(core._ARTIFACTS_BASE_FOR_DRAFT))
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);base=Path(t.name);core.set_draft_artifacts_base(base)
  snapshot={**core.policy_snapshot_from_env(),'intentJson':json.dumps(intent)}
  with patch.dict(os.environ,{'DEPLOOM_BASELINE_INTENT_JSON':json.dumps(intent)}):
   manifest=core.publish_draft_result(run_id='guard-run',workspace_id='ws',project_id='fixture',mode='draft',rows_by_project={'fixture':rows},projects_by_name={},health_by_project={'fixture':core.compute_project_health(rows,'fixture',None)},status=status,partial_reason='test early exit' if status=='DRAFT_PARTIAL' else None,deadline=core.DeadlineClock(None),settings_snapshot=snapshot,input_hashes={'fixture':'original-input-hash'},**kwargs)
  folder=base/'runs/guard-run/draft';return manifest,json.loads((folder/'plan.json').read_text(encoding='utf-8')),(folder/'prompt.md').read_text(encoding='utf-8')

 def test_common_publication_rejects_scope_and_wrong_exact(self):
  rows=[row('held','3.0.0'),row('sample','3.0.0')];original=dataclasses.asdict(rows[0])
  intent={'objective':'explicit-version-targets','mutablePackages':['sample'],'exactTargets':{'sample':'2.0.0'}}
  manifest,plan,prompt=self.publish(rows,intent)
  self.assertEqual(0,plan['counts']['proposed'])
  self.assertEqual(2,plan['counts']['total']);self.assertEqual(2,manifest['metadata']['postPlanScopeTotal'])
  self.assertNotEqual('feasible',manifest['metadata']['postPlanGoal'])
  self.assertEqual('DRAFT_PARTIAL',manifest['status'])
  self.assertEqual('NOT_VERIFIED',manifest['verificationStatus'])
  self.assertEqual('original-input-hash',manifest['inputHashes']['fixture'])
  self.assertEqual(original,dataclasses.asdict(rows[0]),'publication cannot rewrite planner input')
  self.assertTrue(all(r['target'] is None and r['targetYellow'] is None and r['targetGreen'] is None for r in plan['proposals'][0]['rows']))

 def test_complete_valid_contract_and_keep_current_are_preserved(self):
  rows=[row('sample'),row('held','1.0.0')];rows[1].planner_deferred=True
  intent={'objective':'explicit-version-targets','mutablePackages':['sample'],'exactTargets':{'sample':'2.0.0'}}
  m,p,_=self.publish(rows,intent)
  self.assertEqual('DRAFT_READY',m['status']);self.assertEqual(1,p['counts']['proposed']);self.assertEqual(1,p['counts']['deferred'])
  self.assertEqual('2.0.0',p['proposals'][0]['rows'][0]['target']);self.assertEqual('PLANNING_ONLY',m['authority'])

 def test_guard_checks_keep_current_and_all_target_variants(self):
  for intent in [{'policies':{'sample':'keep-current'}},{'mutablePackages':[]},{'approvedVersionLines':{'sample':[1]}}]:
   with self.subTest(intent=intent):
    m,p,_=self.publish([row()],intent)
    self.assertEqual(0,p['counts']['proposed'])
    self.assertEqual(1,m['metadata']['postPlanScopeTotal'])
  r=row();r.target_green='3.0.0'
  _,p,_=self.publish([r],{'objective':'explicit-version-targets','exactTargets':{'sample':'2.0.0'}})
  self.assertEqual(0,p['counts']['proposed'])

 def test_early_budget_exit_cli_keeps_inventory_and_unknowns(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);project=base/'project';project.mkdir();names=['lib%02d'%i for i in range(33)]
   manifest={'name':'fixture','private':True,'version':'1.0.0','devDependencies':{n:'1.0.0' for n in names}}
   (project/'package.json').write_text(json.dumps(manifest),encoding='utf-8')
   lock={'name':'fixture','lockfileVersion':3,'packages':{'':manifest,**{'node_modules/'+n:{'version':'1.0.0'} for n in names}}}
   (project/'package-lock.json').write_text(json.dumps(lock),encoding='utf-8')
   settings={'root':str(base),'projects':[{'name':'fixture','path':str(project)}],'registry':'https://registry.example.invalid','artifactsDir':str(base/'out')}
   (base/'settings.json').write_text(json.dumps(settings),encoding='utf-8')
   intent={'objective':'explicit-version-targets','mutablePackages':names[:8],'exactTargets':{n:'2.0.0' for n in names[:8]}}
   driver="""import sys,os,json
from pathlib import Path
import dependency_live_roadmap_generator as c
base=Path(sys.argv[1])
def no_network(*a,**kw):raise AssertionError('network forbidden')
c.requests.sessions.Session.request=no_network
def scan(*a,**kw):
 rows=kw['draft_sink']
 for r in rows[:29]:
  r.latest_version='3.0.0';r.current_vulns='0';r.draft_scan_state='done'
  for k in ['min_no_critical','min_no_high','min_no_vuln']:setattr(r,k,'1.0.0')
  for k in ['min_lag_12m','min_lag_9m','min_lag_6m','min_lag_3m']:setattr(r,k,'2.0.0')
  for k in ['target_default','target_yellow','target_green']:setattr(r,k,'3.0.0')
 rows[0].target_default=rows[0].target_yellow=rows[0].target_green='2.0.0'
 raise c.DraftBudgetExceeded('network-read')
c.analyze_project=scan
sys.argv=['core','--settings',str(base/'settings.json'),'--draft-baseline','--run-id','early-cli','--no-history-snapshot','--skip-release-intel','--artifacts-dir',str(base/'out'),'--lockfile-mode','validate']
c.main()
"""
   env={**os.environ,'DEPLOOM_BASELINE_INTENT_JSON':json.dumps(intent),'PYTHONDONTWRITEBYTECODE':'1'}
   r=subprocess.run([sys.executable,'-B','-c',driver,str(base)],cwd=Path(core.__file__).parent,env=env,capture_output=True,text=True,encoding='utf-8',timeout=30)
   self.assertEqual(0,r.returncode,r.stderr[-4000:])
   out=base/'out/runs/early-cli/draft';m=json.loads((out/'result.json').read_text(encoding='utf-8'));p=json.loads((out/'plan.json').read_text(encoding='utf-8'))
   self.assertEqual('DRAFT_PARTIAL',m['status']);self.assertEqual(0,p['counts']['proposed'])
   self.assertEqual(33,p['counts']['total']);self.assertEqual(33,m['metadata']['postPlanScopeTotal']);self.assertEqual(27,m['metadata']['postPlanPolicyRequired'])
   self.assertEqual(0,m['metadata']['postPlanLagOk']);self.assertNotEqual('feasible',m['metadata']['postPlanGoal'])
   self.assertEqual(29,m['metadata']['metadataKnown']);self.assertEqual(4,m['metadata']['securityUnknown']);self.assertEqual(4,m['metadata']['pending'])
   self.assertEqual(8,p['counts']['planning-incomplete']);self.assertEqual(25,p['counts']['deferred'])
   self.assertEqual(intent['exactTargets'],m['decisionContract']['exactTargets']);self.assertEqual('PLANNING_ONLY',m['authority']);self.assertEqual('NOT_VERIFIED',m['verificationStatus']);self.assertEqual('UNKNOWN',m['compatibility'])
   self.assertTrue(all(r['target'] is None for r in p['proposals'][0]['rows']))

 def test_partial_without_planning_suppresses_even_matching_exact_candidate(self):
  r=row();r.min_lag_12m=r.min_lag_9m=r.min_lag_6m=r.min_lag_3m='1.0.0'
  intent={'objective':'explicit-version-targets','mutablePackages':['sample'],'exactTargets':{'sample':'2.0.0'}}
  with patch.object(core.requests.sessions.Session,'request',side_effect=AssertionError('no network')), patch.object(core,'solve_z3_exact',side_effect=AssertionError('no solving')):
   m,p,_=self.publish([r],intent,status='DRAFT_PARTIAL',planning_complete=False)
  self.assertEqual(0,p['counts']['proposed']);self.assertEqual(1,p['counts']['planning-incomplete'])
  self.assertEqual('unknown',m['metadata']['postPlanGoal']);self.assertEqual(1,m['metadata']['postPlanScopeTotal'])
  self.assertEqual(1,m['metadata']['planningUnknown']);self.assertEqual(1,m['metadata']['unknown'])
  self.assertEqual(0,m['metadata']['securityUnknown'],'known current-version evidence is not erased')
  self.assertEqual('2.0.0',r.target_default,'the raw observation is retained on the planner input')

 def test_unknown_security_and_late_partial_are_preserved(self):
  r=row();r.current_vulns='unknown'
  m,p,_=self.publish([r],{},status='DRAFT_PARTIAL',planning_complete=False)
  self.assertEqual(1,m['metadata']['securityUnknown']);self.assertEqual(1,m['metadata']['postPlanSecurityUnknown'])
  self.assertEqual(0,p['counts']['proposed']);self.assertNotEqual('feasible',m['metadata']['postPlanGoal'])
  m,p,_=self.publish([row()],{'objective':'explicit-version-targets','exactTargets':{'sample':'2.0.0'}},status='DRAFT_PARTIAL',planning_complete=True)
  self.assertEqual('DRAFT_PARTIAL',m['status']);self.assertEqual(1,p['counts']['proposed'])

if __name__=='__main__':unittest.main()
