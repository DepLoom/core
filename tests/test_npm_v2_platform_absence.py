"""Explicit v2 archive omission agrees with the legacy lock view."""
import copy,unittest
import test_npm_platform_absence as fixture
from resolved_dependency_state import MaterializedDependencyObligationError
from npm_platform_obligations import observe_node_host

class PlatformV2AbsenceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.host=observe_node_host()
 def setUp(self):
  self.f=fixture.PlatformAbsenceTests();self.f.host=self.host;self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.f.lock['lockfileVersion']=2;self.f.rules['kind']='NPM_V2_SRI_PLATFORM_ABSENCE_V1';foreign=self.f.lock['packages']['node_modules/foreign']
  self.f.lock['dependencies']={'held':{'version':'1.0.0','requires':{'foreign':'^1.0.0'}},'foreign':{k:copy.deepcopy(foreign[k]) for k in ('version','optional','integrity','resolved')}}
 def test_exact_archive_and_two_views_keep_denominator(self):
  p=self.f.compile();self.f.physical();r=self.f.observe(p);self.assertEqual(r['instanceCount'],2);self.assertEqual(r['platformInapplicableInstanceCount'],1)
 def test_v3_rule_cannot_promote_v2(self):
  self.f.rules['kind']='NPM_V3_SRI_PLATFORM_ABSENCE_V1'
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'LOCK_UNSUPPORTED'):self.f.compile()
 def test_wrong_legacy_version(self):
  self.f.lock['dependencies']['foreign']['version']='1.0.1'
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_VIEW_MISMATCH'):self.f.compile()
 def test_wrong_legacy_optional(self):
  self.f.lock['dependencies']['foreign']['optional']=False
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_VIEW_MISMATCH'):self.f.compile()
 def test_wrong_legacy_owner_range(self):
  self.f.lock['dependencies']['held']['requires']['foreign']='*'
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_VIEW_REQUIREMENTS_MISMATCH'):self.f.compile()
 def test_legacy_missing_record(self):
  del self.f.lock['dependencies']['foreign']
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'V2_VIEW_MISSING'):self.f.compile()

 def test_legacy_only_required_consumer_is_not_ignored(self):
  self.f.lock['dependencies']['legacy-required']={'version':'1.0.0','requires':{'foreign':'^1.0.0'}}
  with self.assertRaises(MaterializedDependencyObligationError):self.f.compile()

 def test_required_consumer_in_both_views_blocks_optional_absence(self):
  self.f.lock['packages']['node_modules/required']={'version':'1.0.0','dependencies':{'foreign':'^1.0.0'}}
  self.f.lock['dependencies']['required']={'version':'1.0.0','requires':{'foreign':'^1.0.0'}}
  with self.assertRaises(MaterializedDependencyObligationError):self.f.compile()

if __name__=='__main__':unittest.main()
