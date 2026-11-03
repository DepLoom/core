"""Actual native guard boundary; no project acceptance is asserted here."""
import hashlib,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from verification_process_supervisor import run_supervised,ProcessSupervisionError
from project_execution_environment import project_execution_environment,project_environment_fingerprint,V2

def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

@unittest.skipUnless(os.name=='nt','Native V2 launch profile is Windows-only')
class TrustedPrePopenTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name)
  self.argv=[sys.executable,'-B','-c','print("NATIVE_GUARD_CHILD")'];self.env=project_execution_environment(os.environ,contract=V2)
  self.context={'invocationId':'a'*32,'operation':'project-command','commandIndex':1,'sealedCommandHash':'b'*64,'profileDigest':'c'*64,'argvDigest':digest(self.argv)}
 def invoke(self,guard,**kw):return run_supervised(self.argv,self.root,base_env=self.env,timeout_seconds=10,expected_project_environment_digest=project_environment_fingerprint(self.env,contract=V2),trusted_pre_popen_guard=guard,trusted_pre_popen_context=self.context,**kw)
 def test_actual_native_success_links_immutable_observation(self):
  seen=[]
  def guard(e):
   seen.append(e);self.assertEqual(e['actualCwd'],str(self.root));self.assertEqual(e['actualArgv'],tuple(self.argv))
   with self.assertRaises(TypeError):e['actualEnv']['SHOULD_NOT_APPEAR']='bad'
   return {'role':'final','inputBindingHash':'d'*64}
  result=self.invoke(guard);self.assertEqual(result.returncode,0);self.assertIn('NATIVE_GUARD_CHILD',result.stdout);self.assertEqual(len(seen),1)
  witness=result.guarded_spawn_witness;self.assertTrue(witness['spawnStarted']);self.assertGreater(witness['nativePid'],0);self.assertEqual(witness['prePopenObservationHash'],seen[0]['prePopenObservationHash']);self.assertEqual(witness['nativeProcessResultId'],seen[0]['nativeProcessResultId']);self.assertEqual(result.supervision.descendants_remaining,0)
 def test_exception_or_invalid_approval_prevents_popen(self):
  def reject(e):raise RuntimeError('OWNED_INPUT_REJECTED')
  for guard,error in [(reject,RuntimeError),(lambda e:True,ProcessSupervisionError)]:
   with self.subTest(guard=guard),patch('verification_process_supervisor.subprocess.Popen') as popen:
    with self.assertRaises(error):self.invoke(guard)
    popen.assert_not_called()
 def test_context_mismatch_or_json_callback_prevents_popen(self):
  for mutation in [('argvDigest','f'*64),('commandIndex',True),('invocationId','wrong')]:
   old=self.context[mutation[0]];self.context[mutation[0]]=mutation[1]
   with self.subTest(field=mutation[0]),patch('verification_process_supervisor.subprocess.Popen') as popen:
    with self.assertRaises(ProcessSupervisionError):self.invoke(lambda e:None)
    popen.assert_not_called()
   self.context[mutation[0]]=old
  with patch('verification_process_supervisor.subprocess.Popen') as popen:
   with self.assertRaises(ProcessSupervisionError):self.invoke({'callback':'CALLER_JSON'})
   popen.assert_not_called()
 def test_unselected_guard_does_not_fabricate_witness(self):
  result=self.invoke(lambda e:None);self.assertEqual(result.returncode,0);self.assertFalse(hasattr(result,'guarded_spawn_witness'))
 def test_popen_failure_never_returns_started_witness(self):
  with patch('verification_process_supervisor.subprocess.Popen',side_effect=OSError('ACTUAL_SPAWN_FAILED')):
   with self.assertRaisesRegex(OSError,'ACTUAL_SPAWN_FAILED'):self.invoke(lambda e:{'role':'private','inputBindingHash':'d'*64})

class AdaptedEnvironmentDenialTests(unittest.TestCase):
 def test_supervision_marker_cannot_be_hidden_from_exact_environment_identity(self):
  with tempfile.TemporaryDirectory() as raw:
   env=project_execution_environment(os.environ,contract=V2)
   with patch('verification_process_supervisor._LINUX_SUBREAPER',True),patch('verification_process_supervisor.subprocess.Popen') as popen:
    with self.assertRaisesRegex(ProcessSupervisionError,'PROJECT_ACTUAL_LAUNCH_ENVIRONMENT_MISMATCH'):
     run_supervised([sys.executable,'-c','print("MUST_NOT_RUN")'],Path(raw),base_env=env,timeout_seconds=5,expected_project_environment_digest=project_environment_fingerprint(env,contract=V2))
    popen.assert_not_called()

if __name__=='__main__':unittest.main()
