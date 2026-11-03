"""The v3 physical graph retains the complete v2 negative-control suite."""
import copy,json,unittest
from pathlib import Path
import importlib.util
_spec=importlib.util.spec_from_file_location('_v3_fixture_'+Path(__file__).stem,Path(__file__).with_name('test_npm_dependency_obligations.py'))
fixtures=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(fixtures)
from resolved_dependency_state import compile_npm_dependency_obligations,MaterializedDependencyObligationError

class NpmV3DependencyObligationTests(fixtures.NpmDependencyObligationTests):
    def setUp(self):
        super().setUp();self.before['lockfileVersion']=3;self.after['lockfileVersion']=3
    def test_v3_plan_identifies_root_format_without_legacy_tree(self):
        self.prepare();self.assertEqual(self.plan['kind'],'APPROVED_NPM_V3_INSTANCE_OBLIGATIONS')
        self.assertEqual(self.observe()['instanceCount'],3)
    def test_mixed_versions_and_noninteger_versions_are_not_converted(self):
        for a,b in [(2,3),(3,2),(1,1),(True,True),(3.0,3.0)]:
            old,new=copy.deepcopy(self.before),copy.deepcopy(self.after);old['lockfileVersion']=a;new['lockfileVersion']=b
            with self.subTest(before=a,after=b),self.assertRaisesRegex(MaterializedDependencyObligationError,'LOCK_UNSUPPORTED'):
                compile_npm_dependency_obligations(json.dumps(old).encode(),json.dumps(new).encode(),exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target'],delta_digest='a'*64,scope_digest='b'*64)
    def test_v3_conflicting_legacy_tree_is_not_silently_ignored(self):
        self.after['dependencies']={'target':{'version':'99.0.0'}}
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'LOCK_UNSUPPORTED'):self.prepare()

if __name__=='__main__':unittest.main()
