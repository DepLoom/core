import base64,json,os,subprocess,unittest
from verification_stage_checkpoint import pinned_inline_node_invocation,file_digest

def command(body):
    code="eval(Buffer.from('"+base64.b64encode(body).decode("ascii")+"','base64').toString('utf8'))"
    return "node -e "+json.dumps(code)

class InlineNodeTests(unittest.TestCase):
    def environment(self):
        env=dict(os.environ);env.pop("NODE_OPTIONS",None);env.pop("NODE_PATH",None);return env
    def test_real_node_receives_exact_argument_and_executes_pinned_body(self):
        body=b"console.log(JSON.stringify({argv:process.execArgv,exe:process.execPath,marker:'PINNED_BODY_EXECUTED'}));"
        env=self.environment();inv=pinned_inline_node_invocation(command(body),env)
        result=subprocess.run(inv["argv"],env=env,capture_output=True,text=True,encoding="utf-8",timeout=10,check=True)
        observed=json.loads(result.stdout)
        self.assertEqual(observed["argv"],["-e",inv["argv"][2]])
        self.assertEqual(observed["marker"],"PINNED_BODY_EXECUTED")
        self.assertEqual(file_digest(observed["exe"]),inv["nodeExecutableSha256"])
    def test_malformed_encoding_wrapper_and_oversize_fail_before_execution(self):
        env=self.environment()
        for value in (command(b"x")+" && echo fake",command(b"x").replace("base64","hex"),command(b"x").replace("eA==","***"),command(b"x"*2049),command(b"\xff")):
            with self.subTest(value=value[:60]),self.assertRaises(ValueError):pinned_inline_node_invocation(value,env)
    def test_oversized_command_rejected_before_base64_decode(self):
        from unittest.mock import patch
        with patch("base64.b64decode",side_effect=AssertionError("decode must not run")) as decoder:
            with self.assertRaisesRegex(ValueError,"INLINE_NODE_BODY_OR_WRAPPER_UNPROVEN"):
                pinned_inline_node_invocation(command(b"x"*10000),self.environment())
            decoder.assert_not_called()
    def test_external_loader_unproven_and_other_commands_remain_legacy(self):
        env=self.environment()
        for name in ("NODE_OPTIONS","NODE_PATH"):
            with self.assertRaisesRegex(ValueError,"INLINE_NODE_EXTERNAL_LOADER_UNPROVEN"):
                pinned_inline_node_invocation(command(b"console.log(1)"),{**env,name:"external"})
        self.assertIsNone(pinned_inline_node_invocation("npm test",env))

if __name__=="__main__":unittest.main()
