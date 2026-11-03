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
        for lock in (self.before,self.after):
            if lock['lockfileVersion']!=2:continue
            legacy={}
            for location,row in sorted(lock['packages'].items(),key=lambda item:(item[0].count('node_modules/'),item[0])):
                if not location:continue
                segments=location.split('node_modules/')[1:];tree=legacy
                for parent in segments[:-1]:tree=tree[parent.rstrip('/')].setdefault('dependencies',{})
                install=segments[-1];canonical=row.get('name',install)
                value={k:v for k,v in row.items()if k in ('resolved','integrity','optional','dev','devOptional')}
                value['version']='npm:'+canonical+'@'+row['version']if canonical!=install else row['version']
                requirements={**row.get('dependencies',{}),**row.get('optionalDependencies',{})}
                if requirements:value['requires']=requirements
                tree[install]=value
            lock['dependencies']=legacy
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
    def test_empty_unlocked_dot_directory_is_not_an_installed_package(self):
        self.prepare();before=self.observe()
        for location in ['node_modules/.generated-empty','node_modules/target/node_modules/.generated-empty']:
            (self.root/location).mkdir(parents=True)
        observed=[]
        after=observe_npm_dependency_obligations(self.root,self.plan,source_origin_digest='c'*64,resolved_state_key='d'*64,auxiliary_directory_observer=observed.append)
        self.assertEqual(after,before);self.assertEqual(len(observed[0]),2)
        self.assertEqual(after['instanceCount'],3);self.assertEqual(after['heldInstanceCount'],2)
    def test_nonempty_dot_directory_and_empty_valid_package_name_remain_unknown(self):
        self.prepare()
        for name,contents in [('.generated-file',{'index.js':'module.exports=1'}),('.generated-package',{'package.json':'{}'}),('.generated-child',{'child/file':'x'}),('unlisted-empty',{}),('@scope/.hidden',{})]:
            p=self.root/'node_modules'/name;p.mkdir(parents=True)
            for relative,value in contents.items():
                f=p/relative;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(value)
            with self.subTest(name=name),self.assertRaises(MaterializedDependencyObligationError):self.observe()
            for f in sorted(p.rglob('*'),reverse=True):
                if f.is_file():f.unlink()
                elif f.is_dir():f.rmdir()
            p.rmdir()
            if name.startswith('@scope/'):(self.root/'node_modules/@scope').rmdir()
    def test_locked_dot_path_is_rejected_before_auxiliary_classification(self):
        for lock in (self.before,self.after):lock['packages']['node_modules/.locked']={'version':'1.0.0'}
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'PATH_UNPROVEN'):self.prepare()

    def test_expected_package_empty_directory_is_still_missing(self):
        self.prepare();(self.root/'node_modules/held/package.json').unlink()
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'PACKAGE_MISSING'):self.observe()
    def test_empty_dot_reparse_is_never_ignored(self):
        import os
        self.prepare();target=self.root/'empty-outside';target.mkdir();link=self.root/'node_modules/.generated-link'
        try:
            if os.name=='nt':
                import subprocess
                env=dict(os.environ);env.update(DEPLOOM_TEST_LINK=str(link),DEPLOOM_TEST_TARGET=str(target))
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                    'New-Item -ItemType Junction -Path $env:DEPLOOM_TEST_LINK -Target $env:DEPLOOM_TEST_TARGET | Out-Null'],
                    env=env,capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode:raise OSError('test junction creation not permitted')
            else:os.symlink(target,link,target_is_directory=True)
        except OSError as exc:self.skipTest('OS does not permit test link: '+str(exc))
        try:
            with self.assertRaisesRegex(MaterializedDependencyObligationError,'REPARSE_UNPROVEN'):self.observe()
        finally:
            if os.name=='nt':link.rmdir()
            else:link.unlink()

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
        with self.assertRaisesRegex(MaterializedDependencyObligationError,'DEPENDENCY_OBLIGATION_V2_ALIAS_UNPROVEN'):self.prepare()
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
