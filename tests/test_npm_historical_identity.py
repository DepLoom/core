"""Historical ASCII case is read compatibility, not new-candidate authority."""
import copy,json,tempfile,time,unittest
from pathlib import Path
from resolved_dependency_state import (compile_npm_dependency_obligations,observe_npm_dependency_obligations,
    _npm_obligation_name,MaterializedDependencyObligationError)
from npm_platform_obligations import _v2_consistent_graph,_resolve,NpmPlatformEvidenceError

def lock():
 return {'lockfileVersion':2,'packages':{'':{'dependencies':{'owner':'1.0.0'}},'node_modules/owner':{'version':'1.0.0','dependencies':{'JSONStream':'^1.3.0'}},'node_modules/JSONStream':{'version':'1.3.5','integrity':'unchanged-host-record'}},
    'dependencies':{'owner':{'version':'1.0.0','requires':{'JSONStream':'^1.3.0'}},'JSONStream':{'version':'1.3.5','integrity':'unchanged-host-record'}}}

class HistoricalIdentityTests(unittest.TestCase):
 def compile(self,before,after=None):
  after=before if after is None else after
  changed=[p for p in set(before['packages'])|set(after['packages']) if p and before['packages'].get(p)!=after['packages'].get(p)]
  return compile_npm_dependency_obligations(json.dumps(before).encode(),json.dumps(after).encode(),exact_targets={},changed_instances=changed,delta_digest='a'*64,scope_digest='b'*64)
 def test_held_mixed_case_manifest_and_edges_physically_match(self):
  data=lock();_v2_consistent_graph(data);plan=self.compile(data)
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'package.json').write_text(json.dumps(data['packages']['']));(root/'package-lock.json').write_text(json.dumps(data))
   for location,row in data['packages'].items():
    if location:
     p=root/location;p.mkdir(parents=True);(p/'package.json').write_text(json.dumps({'name':location.removeprefix('node_modules/'),**row}))
   observed=observe_npm_dependency_obligations(root,plan,source_origin_digest='c'*64,resolved_state_key='d'*64,deadline=time.monotonic()+5)
   self.assertEqual(observed['instanceCount'],2);self.assertEqual(observed['unknownCount'],0)
   self.assertTrue(all(r['held'] for r in plan['instances']))
   self.assertEqual(_resolve(data['packages'],'','JSONStream'),'node_modules/JSONStream')
   self.assertIsNone(_resolve(data['packages'],'','jsonstream'))
   (root/'node_modules/JSONStream/package.json').write_text(json.dumps({'name':'jsonstream','version':'1.3.5'}))
   with self.assertRaisesRegex(MaterializedDependencyObligationError,'IDENTITY_MISMATCH'):
    observe_npm_dependency_obligations(root,plan,source_origin_digest='c'*64,resolved_state_key='d'*64)
 def test_new_or_changed_mixed_case_record_not_authorized(self):
  before=lock()
  for field,value in [('version','1.3.6'),('integrity','changed')]:
   after=copy.deepcopy(before);after['packages']['node_modules/JSONStream'][field]=value
   with self.subTest(field=field),self.assertRaisesRegex(MaterializedDependencyObligationError,'HISTORICAL_INSTANCE_CHANGED'):self.compile(before,after)
  after=copy.deepcopy(before);after['packages']['node_modules/NewHistorical']={'version':'1.0.0'}
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'HISTORICAL_INSTANCE_CHANGED'):self.compile(before,after)
 def test_casefold_collision_is_not_a_second_legacy_identity(self):
  data=lock();data['packages']['node_modules/jsonstream']={'version':'1.3.5'};data['dependencies']['jsonstream']={'version':'1.3.5'}
  with self.assertRaises(NpmPlatformEvidenceError):_v2_consistent_graph(data)
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'GRAPH_UNPROVEN'):self.compile(data)
 def test_unsafe_identity_paths_still_reject(self):
  for name in ['../JSONStream','@scope/../../x','JSONStream\x00','JSONStream:evil','JSONStream/extra','JSONStream\\extra','JSONStream%2fother']:
   with self.subTest(name=name),self.assertRaises(MaterializedDependencyObligationError):_npm_obligation_name('node_modules/'+name,{'version':'1.3.5'})
 def test_alias_record_keeps_install_and_canonical_names_separate(self):
  self.assertEqual(_npm_obligation_name('node_modules/alias',{'name':'JSONStream','version':'1.3.5'}),('alias','JSONStream'))
  self.assertEqual(_npm_obligation_name('node_modules/JSONStream',{'version':'1.3.5'}),('JSONStream','JSONStream'))

if __name__=='__main__':unittest.main()
