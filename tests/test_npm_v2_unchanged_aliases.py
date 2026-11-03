"""npm v2 aliases retain exact baseline records and complete incoming edges."""
import copy,json,tempfile,time,unittest
from pathlib import Path
from npm_platform_obligations import _v2_consistent_graph
from resolved_dependency_state import compile_npm_dependency_obligations,observe_npm_dependency_obligations,MaterializedDependencyObligationError

def fixture():
 return {'lockfileVersion':2,'packages':{'':{'dependencies':{'owner':'1.0.0'}},'node_modules/owner':{'version':'1.0.0','dependencies':{'alias':'npm:real@^1.0.0'}},'node_modules/alias':{'name':'real','version':'1.2.3','integrity':'synthetic-held'}},'dependencies':{'owner':{'version':'1.0.0','requires':{'alias':'npm:real@^1.0.0'}},'alias':{'version':'npm:real@1.2.3','integrity':'synthetic-held'}}}

class V2AliasIdentityTests(unittest.TestCase):
 def compile(self,before,after=None):
  after=before if after is None else after
  changed=[p for p in set(before['packages'])|set(after['packages']) if p and before['packages'].get(p)!=after['packages'].get(p)]
  return compile_npm_dependency_obligations(json.dumps(before).encode(),json.dumps(after).encode(),exact_targets={},changed_instances=changed,delta_digest='a'*64,scope_digest='b'*64)
 def test_original_both_view_identity_and_real_physical_edges(self):
  data=fixture();original=copy.deepcopy(data);_v2_consistent_graph(data);plan=self.compile(data)
  self.assertEqual(data,original);self.assertIn('node_modules/alias',plan['unchangedNpmV2Aliases'])
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);(p/'package.json').write_text(json.dumps(data['packages']['']));(p/'package-lock.json').write_text(json.dumps(data))
   for loc,row in data['packages'].items():
    if loc:
     q=p/loc;q.mkdir(parents=True);(q/'package.json').write_text(json.dumps({**row,'name':row.get('name',loc.removeprefix('node_modules/'))}))
   observed=observe_npm_dependency_obligations(p,plan,source_origin_digest='c'*64,resolved_state_key='d'*64,deadline=time.monotonic()+5)
   self.assertEqual(observed['instanceCount'],2);self.assertEqual(observed['unknownCount'],0);self.assertFalse(observed['fullAcceptance'])
   (p/'node_modules/alias/package.json').write_text(json.dumps({'name':'wrong','version':'1.2.3'}))
   with self.assertRaisesRegex(MaterializedDependencyObligationError,'IDENTITY_MISMATCH'):
    observe_npm_dependency_obligations(p,plan,source_origin_digest='c'*64,resolved_state_key='d'*64)
 def test_wrong_legacy_canonical_version_or_sri_rejected(self):
  for key,value in [('version','npm:wrong@1.2.3'),('version','npm:real@1.2.4'),('version','1.2.3'),('integrity','changed')]:
   data=fixture();data['dependencies']['alias'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(MaterializedDependencyObligationError):self.compile(data)
 def test_canonical_identity_or_range_not_guessed(self):
  for spec in ['npm:wrong@^1.0.0','npm:real@^2.0.0','^1.0.0']:
   data=fixture();data['packages']['node_modules/owner']['dependencies']['alias']=spec;data['dependencies']['owner']['requires']['alias']=spec
   with self.subTest(spec=spec),self.assertRaisesRegex(MaterializedDependencyObligationError,'ALIAS_UNPROVEN'):self.compile(data)
 def test_changed_alias_version_sri_and_added_incoming_edge_rejected(self):
  before=fixture()
  for field,value in [('version','1.2.4'),('integrity','changed')]:
   after=copy.deepcopy(before);after['packages']['node_modules/alias'][field]=value;after['dependencies']['alias'][field]='npm:real@'+value if field=='version' else value
   with self.subTest(field=field),self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_ALIAS_CHANGED'):self.compile(before,after)
  after=copy.deepcopy(before);after['packages']['node_modules/consumer']={'version':'1.0.0','dependencies':{'alias':'npm:real@^1.0.0'}};after['dependencies']['consumer']={'version':'1.0.0','requires':{'alias':'npm:real@^1.0.0'}}
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_ALIAS_CHANGED'):self.compile(before,after)
 def test_raw_legacy_flags_cannot_change_and_scoped_alias_is_typed(self):
  before=fixture();after=copy.deepcopy(before);after['dependencies']['alias']['peer']=True
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_ALIAS_CHANGED'):self.compile(before,after)
  data=fixture();data['packages']['node_modules/alias']['name']='@scope/real';data['dependencies']['alias']['version']='npm:@scope/real@1.2.3';data['packages']['node_modules/owner']['dependencies']['alias']='npm:@scope/real@^1';data['dependencies']['owner']['requires']['alias']='npm:@scope/real@^1'
  self.compile(data)
 def test_new_alias_and_orphan_alias_rejected(self):
  before=fixture();after=copy.deepcopy(before);after['packages']['node_modules/second']={'name':'real','version':'1.2.3'};after['dependencies']['second']={'version':'npm:real@1.2.3'}
  with self.assertRaises(MaterializedDependencyObligationError):self.compile(before,after)
  data=fixture();data['packages']['node_modules/owner']['dependencies']={};data['dependencies']['owner']['requires']={}
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'ALIAS_UNPROVEN'):self.compile(data)

if __name__=='__main__':unittest.main()
