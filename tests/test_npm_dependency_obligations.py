"""Physical npm instance/edge observations; no registry or project execution."""
import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from resolved_dependency_state import (compile_npm_dependency_obligations,observe_npm_dependency_obligations,
    MaterializedDependencyObligationError,_canonical_hash)

class NpmDependencyObligationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.before={'lockfileVersion':2,'packages':{'':{'dependencies':{'target':'1.0.0','held':'1.0.0'}},
            'node_modules/target':{'version':'1.0.0','dependencies':{'leaf':'^1.0.0'}},
            'node_modules/held':{'version':'1.0.0','peerDependencies':{'leaf':'^1.0.0'}},
            'node_modules/leaf':{'version':'1.0.0'}}}
        self.after=copy.deepcopy(self.before);self.after['packages']['']['dependencies']['target']='2.0.0';self.after['packages']['node_modules/target']['version']='2.0.0'
    def prepare(self):
        old=json.dumps(self.before).encode();new=json.dumps(self.after).encode()
        self.plan=compile_npm_dependency_obligations(old,new,exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target'],immutable_packages=['held'],delta_digest='a'*64,scope_digest='b'*64)
        (self.root/'package-lock.json').write_bytes(new);(self.root/'package.json').write_text(json.dumps(self.after['packages']['']))
        for row in self.plan['instances']:
            p=self.root/row['path'];p.mkdir(parents=True,exist_ok=True)
            (p/'package.json').write_text(json.dumps({'name':row['name'],'version':row['version'],**row['metadata']}))
    def observe(self):return observe_npm_dependency_obligations(self.root,self.plan,source_origin_digest='c'*64,resolved_state_key='d'*64)
    def test_real_manifests_and_node_edges_cover_held_root(self):
        self.prepare();r=self.observe();self.assertEqual(r['heldInstanceCount'],2);self.assertEqual(r['instanceCount'],3)
        self.assertEqual(r['protectedEdgeCount'],4);self.assertEqual(r['unknownCount'],0);self.assertFalse(r['fullAcceptance'])
        self.assertEqual(r['payloadAuthenticity'],'NOT_ATTESTED')
    def test_held_version_drift_is_not_hidden_by_unchanged_lock(self):
        self.prepare();p=self.root/'node_modules/held/package.json';x=json.loads(p.read_text());x['version']='9.0.0';p.write_text(json.dumps(x))
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'IDENTITY_MISMATCH'):self.observe()
    def test_nested_held_instance_uses_exact_path_and_denominator(self):
        for lock in (self.before,self.after):lock['packages']['node_modules/target/node_modules/leaf']={'version':'1.0.0'}
        self.prepare();self.assertEqual(self.observe()['heldInstanceCount'],3)
        p=self.root/'node_modules/target/node_modules/leaf/package.json';p.unlink()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'PACKAGE_MISSING'):self.observe()
    def test_extra_physical_instance_is_rejected(self):
        self.prepare();p=self.root/'node_modules/unapproved';p.mkdir();(p/'package.json').write_text('{"name":"unapproved","version":"1.0.0"}')
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'INSTANCE_SET_MISMATCH'):self.observe()
    def test_missing_optional_is_unknown_without_an_omission_rule(self):
        for lock in (self.before,self.after):lock['packages']['node_modules/leaf']['optional']=True
        self.prepare();(self.root/'node_modules/leaf/package.json').unlink();(self.root/'node_modules/leaf').rmdir()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'INSTANCE_SET_MISMATCH'):self.observe()
    def test_peer_is_resolved_at_parent_not_own_nested_dependency(self):
        for lock in (self.before,self.after):
            lock['packages']['node_modules/held']['peerDependencies']['leaf']='^2.0.0'
            lock['packages']['node_modules/held/node_modules/leaf']={'version':'2.0.0'}
        self.prepare()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'EDGE_MISMATCH'):self.observe()
    def test_alias_canonical_identity_is_separate_from_install_name(self):
        for lock in (self.before,self.after):
            lock['packages']['']['dependencies']['alias']='npm:leaf@^1.0.0';lock['packages']['node_modules/alias']={'name':'leaf','version':'1.0.0'}
        self.prepare();self.assertEqual(self.observe()['instanceCount'],4)
    def test_ordinary_edge_cannot_borrow_implicit_alias_identity(self):
        for lock in (self.before,self.after):lock['packages']['node_modules/held']['name']='unrelated'
        self.prepare()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'EDGE_IDENTITY_MISMATCH'):self.observe()
    def test_bundled_lock_mode_is_not_an_ordinary_physical_obligation(self):
        for value in [True,1,'true']:
            old=copy.deepcopy(self.before);new=copy.deepcopy(self.after)
            for lock in (old,new):lock['packages']['node_modules/held']['inBundle']=value
            with self.subTest(value=value),self.assertRaisesRegex(MaterializedDependencyObligationError,'BUNDLE_OR_LINK_UNSUPPORTED'):
                compile_npm_dependency_obligations(json.dumps(old).encode(),json.dumps(new).encode(),exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target'],delta_digest='a'*64,scope_digest='b'*64)
    def test_bundle_and_invalid_link_metadata_are_rejected_in_lock_or_physical_manifest(self):
        for key,value in [('link',1),('bundleDependencies',['leaf']),('bundledDependencies',True)]:
            old=copy.deepcopy(self.before);new=copy.deepcopy(self.after)
            for lock in (old,new):lock['packages']['node_modules/held'][key]=value
            with self.subTest(key=key),self.assertRaises(MaterializedDependencyObligationError):
                compile_npm_dependency_obligations(json.dumps(old).encode(),json.dumps(new).encode(),exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target'],delta_digest='a'*64,scope_digest='b'*64)
        self.prepare();p=self.root/'node_modules/held/package.json';value=json.loads(p.read_text());value['bundledDependencies']=['leaf'];p.write_text(json.dumps(value))
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'BUNDLED_UNSUPPORTED'):self.observe()

    def test_metadata_and_lock_drift_fail_closed(self):
        self.prepare();p=self.root/'node_modules/target/package.json';old=p.read_text();x=json.loads(old);x['dependencies']['leaf']='^2.0.0';p.write_text(json.dumps(x))
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'METADATA_UNPROVEN'):self.observe()
        p.write_text(old);(self.root/'package-lock.json').write_bytes(b'{}')
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'LOCK_DRIFT'):self.observe()
    def test_plan_mutation_and_case_aliases_are_rejected(self):
        self.prepare();self.plan['instances'][0]['version']='9.0.0'
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'PLAN_UNPROVEN'):self.observe()
        self.after['packages']['node_modules/Held']={'version':'1.0.0'}
        with self.assertRaises(MaterializedDependencyObligationError):self.prepare()
    def test_optional_dependency_override_uses_effective_specifier(self):
        for lock in (self.before,self.after):
            lock['packages']['node_modules/target']['dependencies']['leaf']='^2.0.0'
            lock['packages']['node_modules/target']['optionalDependencies']={'leaf':'^1.0.0'}
        self.prepare();self.assertEqual(self.observe()['instanceCount'],3)
    def test_expired_guard_budget_returns_unknown_not_partial_success(self):
        import time
        self.prepare()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'DEADLINE_EXCEEDED'):
            observe_npm_dependency_obligations(self.root,self.plan,source_origin_digest='c'*64,resolved_state_key='d'*64,deadline=time.monotonic()-1)

    def test_protected_delta_and_unlisted_changed_instance_are_rejected(self):
        self.after['packages']['node_modules/held']['version']='2.0.0'
        old=json.dumps(self.before).encode();new=json.dumps(self.after).encode()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'DELTA_MISMATCH'):
            compile_npm_dependency_obligations(old,new,exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target'],delta_digest='a'*64,scope_digest='b'*64)
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'PROTECTED_DELTA'):
            compile_npm_dependency_obligations(old,new,exact_targets={'target':'2.0.0'},changed_instances=['node_modules/target','node_modules/held'],immutable_packages=['held'],delta_digest='a'*64,scope_digest='b'*64)

if __name__=='__main__':unittest.main()
