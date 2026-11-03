"""Safe archive membership and immutable bundled payload; no npm runs."""
import base64,copy,hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
from npm_bundle_obligations import prove_unchanged_owner,compare_installed_owner,NpmBundleEvidenceError

class BundleObligationTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.project=self.root/'project';self.owner='node_modules/owner';self.child=self.owner+'/node_modules/leaf'
  self.om={'name':'owner','version':'1.0.0','dependencies':{'leaf':'^1.0.0'},'bundleDependencies':['leaf']};self.cm={'name':'leaf','version':'1.0.0'}
  self.files={'package/package.json':json.dumps(self.om).encode(),'package/index.js':b'module.exports=42','package/node_modules/leaf/package.json':json.dumps(self.cm).encode(),'package/node_modules/leaf/index.js':b'module.exports=1'}
  self.archive=self.root/'owner.tgz';self.build_archive()
  for name,raw in self.files.items():
   path=self.project/self.owner/name.removeprefix('package/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
  self.before={'lockfileVersion':2,'packages':{'':{'dependencies':{'owner':'1.0.0'}},self.owner:{'version':'1.0.0','resolved':'https://registry.npmjs.org/owner/-/owner-1.0.0.tgz','integrity':self.sri(),'dependencies':{'leaf':'^1.0.0'},'bundleDependencies':['leaf']},self.child:{'version':'1.0.0','inBundle':True}},'dependencies':{'owner':{'version':'1.0.0','resolved':'https://registry.npmjs.org/owner/-/owner-1.0.0.tgz','integrity':self.sri(),'requires':{'leaf':'^1.0.0'},'dependencies':{'leaf':{'version':'1.0.0','bundled':True}}}}};self.after=copy.deepcopy(self.before)
 def sri(self):return 'sha512-'+base64.b64encode(hashlib.sha512(self.archive.read_bytes()).digest()).decode()
 def build_archive(self,extra=()):
  with tarfile.open(self.archive,'w:gz') as tf:
   for name,raw in self.files.items():
    m=tarfile.TarInfo(name);m.size=len(raw);tf.addfile(m,io.BytesIO(raw))
   for m,raw in extra:tf.addfile(m,io.BytesIO(raw) if raw is not None else None)
 def repin(self):
  for lock in (self.before,self.after):lock['packages'][self.owner]['integrity']=self.sri();lock['dependencies']['owner']['integrity']=self.sri()
 def prove(self):return prove_unchanged_owner(self.before,self.after,self.owner,self.archive,self.project)
 def reject(self):
  with self.assertRaises((NpmBundleEvidenceError,OSError)):self.prove()
 def test_scoped_proof_is_not_execution_or_node_proof(self):
  p=self.prove();self.assertEqual(p['memberCount'],1);self.assertFalse(p['fullAcceptance']);self.assertEqual(p['physicalNodeEdges'],'NOT_VERIFIED');r=compare_installed_owner(self.project,p);self.assertEqual(r['status'],'UNCHANGED_BUNDLED_SUBTREE_OBSERVED')
 def test_owner_change(self):self.after['packages'][self.owner]['version']='1.0.1';self.reject()
 def test_sri_mismatch(self):self.archive.write_bytes(self.archive.read_bytes()+b'changed');self.reject()
 def test_registry_source_change(self):self.after['packages'][self.owner]['resolved']='https://other.invalid/pkg';self.reject()
 def test_member_change(self):self.after['packages'][self.child]['version']='1.0.1';self.reject()
 def test_two_view_mismatch(self):self.after['dependencies']['owner']['dependencies']['leaf']['version']='1.0.1';self.reject()
 def test_code_tamper_without_manifest_change(self):(self.project/self.child/'index.js').write_bytes(b'evil');self.reject()
 def test_extra_nonpackage_file(self):(self.project/self.owner/'unexpected.js').write_bytes(b'evil');self.reject()
 def test_extra_archive_package(self):
  raw=b'{"name":"extra","version":"1.0.0"}';m=tarfile.TarInfo('package/node_modules/extra/package.json');m.size=len(raw);self.build_archive([(m,raw)]);self.repin();self.reject()
 def test_missing_manifest(self):del self.files['package/node_modules/leaf/package.json'];self.build_archive();self.repin();self.reject()
 def test_path_and_duplicate_and_link_negatives(self):
  for kind in ('traversal','absolute','duplicate','case','symlink','hardlink','special','pax'):
   with self.subTest(kind=kind):
    m=tarfile.TarInfo('package/extra');raw=b'x';m.size=1
    if kind=='traversal':m.name='package/../evil'
    if kind=='absolute':m.name='/package/evil'
    if kind=='duplicate':m.name='package/index.js'
    if kind=='case':m.name='package/INDEX.js'
    if kind in ('symlink','hardlink'):m.type=tarfile.SYMTYPE if kind=='symlink' else tarfile.LNKTYPE;m.linkname='index.js';m.size=0;raw=None
    if kind=='special':m.type=tarfile.FIFOTYPE;m.size=0;raw=None
    if kind=='pax':m.pax_headers={'SCHILY.xattr.security.test':'unknown'}
    self.build_archive([(m,raw)]);self.repin();self.reject()
 def test_installed_code_deletion_or_addition(self):
  p=self.prove();target=self.project/self.child/'index.js';target.unlink()
  with self.assertRaises(NpmBundleEvidenceError):compare_installed_owner(self.project,p)
  target.write_bytes(b'module.exports=1');(self.project/self.child/'extra.js').write_bytes(b'evil')
  with self.assertRaises(NpmBundleEvidenceError):compare_installed_owner(self.project,p)
 def test_file_permission_drift(self):
  import os,stat
  p=self.prove();target=self.project/self.child/'index.js';mode=target.stat().st_mode
  try:
   os.chmod(target,stat.S_IREAD)
   with self.assertRaises(NpmBundleEvidenceError):compare_installed_owner(self.project,p)
  finally:os.chmod(target,mode)
 def test_forged_control_digest(self):
  p=self.prove();p['baselineSubtreeDigest']='0'*64
  with self.assertRaises(NpmBundleEvidenceError):compare_installed_owner(self.project,p)

 def add_ordinary_nested(self):
  path=self.owner+'/node_modules/other';archive=self.root/'other.tgz';manifest={'name':'other','version':'1.0.0'}
  files={'package.json':json.dumps(manifest).encode(),'index.js':b'module.exports=7'}
  with tarfile.open(archive,'w:gz') as tf:
   for name,raw in files.items():
    m=tarfile.TarInfo('package/'+name);m.size=len(raw);tf.addfile(m,io.BytesIO(raw))
    f=self.project/path/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
  record={'version':'1.0.0','resolved':'https://registry.npmjs.org/other/-/other-1.0.0.tgz','integrity':'sha512-'+base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()}
  for lock in (self.before,self.after):lock['packages'][path]=copy.deepcopy(record);lock['dependencies']['owner']['dependencies']['other']=copy.deepcopy(record)
  return path,archive
 def test_ordinary_nested_artifact_requires_own_archive(self):
  self.add_ordinary_nested();self.reject()
 def test_ordinary_nested_sri_bound_payload(self):
  path,archive=self.add_ordinary_nested();p=prove_unchanged_owner(self.before,self.after,self.owner,self.archive,self.project,ordinary_nested_archives={path:archive})
  self.assertIn(path,p['ordinaryNestedProofs']);self.assertEqual(p['memberCount'],1);self.assertEqual(compare_installed_owner(self.project,p)['memberCount'],1)
 def test_ordinary_nested_payload_tamper(self):
  path,archive=self.add_ordinary_nested();(self.project/path/'index.js').write_bytes(b'evil')
  with self.assertRaises(NpmBundleEvidenceError):prove_unchanged_owner(self.before,self.after,self.owner,self.archive,self.project,ordinary_nested_archives={path:archive})

 def compile_bound_fixture(self):
  from resolved_dependency_state import compile_npm_dependency_obligations
  from npm_bundle_obligations import digest
  raw=json.dumps(self.before).encode();(self.project/'package-lock.json').write_bytes(raw);(self.project/'package.json').write_text(json.dumps(self.before['packages']['']))
  proof=self.prove();rules={'schemaVersion':1,'kind':'UNCHANGED_NPM_V2_BUNDLED_OWNER_RULES_V1','baselineProjectPath':str(self.project.resolve()),'baselineLockSha256':hashlib.sha256(raw).hexdigest(),'owners':[{'instance':self.owner,'archivePath':str(self.archive.resolve()),'baselineSubtreeDigest':proof['baselineSubtreeDigest'],'ordinaryNestedArchives':{}}]}
  plan=compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64,bundled_owner_rules=rules)
  return plan
 def test_compiler_without_proof_retains_bundle_ban(self):
  from resolved_dependency_state import compile_npm_dependency_obligations,MaterializedDependencyObligationError
  raw=json.dumps(self.before).encode()
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'BUNDLED_UNSUPPORTED'):compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64)
 def test_owner_compiler_observer_full_denominator(self):
  from resolved_dependency_state import observe_npm_dependency_obligations
  plan=self.compile_bound_fixture();self.assertEqual(len(plan['instances']),2)
  result=observe_npm_dependency_obligations(self.project,plan,source_origin_digest='c'*64,resolved_state_key='d'*64)
  self.assertEqual(result['instanceCount'],2);self.assertEqual(result['bundledMemberCount'],1);self.assertFalse(result['fullAcceptance'])
 def test_owner_observer_rejects_code_drift(self):
  from resolved_dependency_state import observe_npm_dependency_obligations,MaterializedDependencyObligationError
  plan=self.compile_bound_fixture();(self.project/self.child/'index.js').write_bytes(b'changed')
  with self.assertRaisesRegex(MaterializedDependencyObligationError,'BUNDLE_UNPROVEN'):observe_npm_dependency_obligations(self.project,plan,source_origin_digest='c'*64,resolved_state_key='d'*64)

if __name__=='__main__':unittest.main()
