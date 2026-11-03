import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import draft_npm_preflight as preflight

class NpmPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.manifest = self.source / 'package.json'
        self.manifest.write_text(json.dumps({'name': 'fixture', 'private': True, 'dependencies': {'left': '^1.0.0', 'right': '1.0.0'}}), encoding='utf-8')
        self.rows = [{'package': name, 'current': '1.0.0', 'target': '2.0.0'} for name in ['left', 'right']]
        self.plan = {'proposals': [{'project': 'fixture', 'rows': self.rows}]}
        self.binary = self.base / 'node'
        self.binary.write_bytes(b'node-identity')
        self.cli = self.base / 'npm-cli.js'
        self.cli.write_bytes(b'npm-identity')

    def validate(self, runner, remaining=lambda: None):
        with patch.object(preflight, '_npm_command', return_value=[str(self.binary), str(self.cli)]), patch.object(preflight, 'run_supervised', side_effect=runner):
            return preflight.validate_draft_plan(self.plan, {'fixture': self.source}, artifacts_dir=self.base / 'out', registry='https://registry.example.invalid/', options={'offline': True, 'cache': str(self.base / 'cache'), 'timeoutSeconds': 60}, remaining=remaining)

    def test_eresolve_is_context_bound_failure_and_source_is_preserved(self):
        original = self.manifest.read_bytes()
        def runner(argv, cwd, **kwargs):
            for flag in ['--strict-peer-deps=true', '--engine-strict=true', '--ignore-scripts=true', '--force=false', '--legacy-peer-deps=false', '--offline=true']:
                self.assertIn(flag, argv)
            self.assertNotEqual(self.source, cwd)
            self.assertFalse((cwd / 'package-lock.json').exists())
            return subprocess.CompletedProcess(argv, 1, 'npm error code ERESOLVE\n', None)
        result = self.validate(runner)
        self.assertEqual('RESOLUTION_FAILED', result['status'])
        self.assertFalse(result['learningAllowed'])
        self.assertEqual(original, self.manifest.read_bytes())
        self.assertTrue(result['projects']['fixture']['sourceUnchanged'])

    def test_cache_miss_and_timeout_remain_unknown(self):
        result = self.validate(lambda *a, **k: subprocess.CompletedProcess(a, 1, 'npm error code ENOTCACHED\n', None))
        self.assertEqual('UNKNOWN', result['status'])
        self.assertFalse(result['learningAllowed'])
        def timeout(*a, **k):
            raise subprocess.TimeoutExpired('npm', 1)
        result = self.validate(timeout)
        self.assertEqual('UNKNOWN', result['status'])
        self.assertEqual('RESOLVER_TIMEOUT', result['projects']['fixture']['code'])

    def test_success_requires_exact_lock_assignment_but_is_not_install_proof(self):
        def runner(argv, cwd, **kwargs):
            self.assertEqual(1, kwargs['timeout_seconds'])
            (cwd / 'package-lock.json').write_text(json.dumps({'packages': {'node_modules/left': {'version': '2.0.0'}, 'node_modules/right': {'version': '2.0.0'}}}), encoding='utf-8')
            return subprocess.CompletedProcess(argv, 0, '', None)
        result = self.validate(runner, remaining=lambda: 1.8)
        self.assertEqual('RESOLUTION_PASSED', result['status'])
        self.assertEqual('NOT_RUN', result['installation'])
        self.assertEqual('NOT_RUN', result['runtime'])
        self.assertFalse(result['learningAllowed'])
        bad = self.validate(lambda *a, **k: subprocess.CompletedProcess(a, 0, '', None))
        self.assertEqual('UNKNOWN', bad['status'])

    def test_scope_and_workspace_gaps_never_invoke_resolver(self):
        def forbidden(*a, **k):
            self.fail('resolver must not run')
        self.plan['proposals'][0]['rows'] = self.rows[:1]
        result = self.validate(forbidden)
        self.assertEqual('ROOT_INVENTORY_MISMATCH', result['projects']['fixture']['code'])
        self.plan['proposals'][0]['rows'] = self.rows
        obj=json.loads(self.manifest.read_text());obj['workspaces']=['packages/*'];self.manifest.write_text(json.dumps(obj),encoding='utf-8')
        result = self.validate(forbidden)
        self.assertEqual('UNSUPPORTED_PROJECT_TOPOLOGY', result['projects']['fixture']['code'])

    def test_expired_budget_does_not_run_or_reset_the_clock(self):
        result=self.validate(lambda *a, **k: self.fail('expired budget'), remaining=lambda: .5)
        self.assertEqual('UNKNOWN', result['status'])
        self.assertEqual('DRAFT_BUDGET_EXHAUSTED', result['projects']['fixture']['code'])

    def test_source_change_invalidates_even_a_successful_exit(self):
        def runner(argv,cwd,**kwargs):
            self.manifest.write_text('{"changed":true}',encoding='utf-8')
            return subprocess.CompletedProcess(argv,0,'',None)
        result=self.validate(runner)
        self.assertEqual('SOURCE_INPUT_CHANGED',result['projects']['fixture']['code'])
        self.assertEqual('UNKNOWN',result['status'])

    def test_missing_runtime_registry_never_uses_a_default_network_origin(self):
        with patch.object(preflight, 'run_supervised', side_effect=AssertionError('must not run')):
            result=preflight.validate_draft_plan(self.plan, {'fixture':self.source}, artifacts_dir=self.base/'out', registry='', options={}, remaining=lambda:60)
        self.assertEqual('UNKNOWN',result['status'])
        self.assertEqual('REGISTRY_NOT_CONFIGURED',result['projects']['fixture']['code'])

class NpmEntrypointDiscoveryTests(unittest.TestCase):
    def test_explicit_path_is_used_for_all_executable_lookups(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();node=root/'node';node.write_bytes(b'node')
            script=root/'lib/npm/bin/npm-cli.js';script.parent.mkdir(parents=True);script.write_bytes(b'npm')
            def which(name, *, path):
                self.assertEqual(path, 'CALLER_OWNED_PATH')
                return str(node) if name=='node' else str(script) if name=='npm' else None
            with patch.object(preflight.shutil,'which',side_effect=which):
                self.assertEqual(preflight._npm_command(path='CALLER_OWNED_PATH'),[str(node),str(script)])
    def test_missing_caller_toolchain_does_not_fall_back_to_ambient_path(self):
        with patch.object(preflight.shutil,'which',return_value=None) as lookup:
            with self.assertRaises(OSError):preflight._npm_command(path='EMPTY_PATH')
            self.assertTrue(all(c.kwargs=={'path':'EMPTY_PATH'} for c in lookup.call_args_list))

if __name__=='__main__':
    unittest.main()
