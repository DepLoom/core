"""P2.6 adversarial registry guard regression: real local HTTP only, no agent."""
from __future__ import annotations

import http.server
import json
import threading
import unittest
from urllib.parse import urljoin

import dependency_live_roadmap_generator as core
from lockfile_consistency import registry_artifact_url_allowed as lockfile_allowed
from registry_candidate_diagnostics import _identity, safe_registry_artifact_url, summarize_structural_candidates, no_target_diagnostic_code


class ArtifactUrlFailClosedTests(unittest.TestCase):
    def test_benign_registry_paths_and_ports_are_kept(self):
        root = 'https://registry.npmjs.org'
        self.assertTrue(safe_registry_artifact_url(root,root+'/lodash/-/lodash-4.18.1.tgz'))
        nexus = 'https://nexus.example.invalid/repository/npm/'
        for suffix in ('/repository/npm/demo/-/demo-1.2.0.tgz',
                       '/repository/npm/@scope/demo/-/demo-1.2.0.tgz',
                       '/repository/npm/%40scope/demo/-/demo-1.2.0.tgz'):
            self.assertTrue(safe_registry_artifact_url(nexus,'https://nexus.example.invalid'+suffix),suffix)
        self.assertTrue(safe_registry_artifact_url('https://nexus.invalid:443/npm','https://nexus.invalid/npm/a.tgz'))
        self.assertTrue(safe_registry_artifact_url('http://localhost:4873/npm','http://localhost:4873/npm/a.tgz'))

    def test_malformed_and_deceptive_artifacts_are_rejected_not_raised(self):
        reg='https://nexus.example.invalid/repository/npm'
        hostile = (
            'https://a:b@nexus.example.invalid/repository/npm/a.tgz',
            'https://nexus.example.invalid/repository/npm/../private/a.tgz',
            'https://nexus.example.invalid/repository/npm/%2e%2e/private/a.tgz',
            'https://nexus.example.invalid/repository/npm/%252e%252e/private/a.tgz',
            'https://nexus.example.invalid/repository/npm/%25252e%25252e/private/a.tgz',
            'https://nexus.example.invalid/repository/npm/%2f..%2fprivate/a.tgz',
            'https://nexus.example.invalid/repository/npm/%5c..%5cprivate/a.tgz',
            'https://nexus.example.invalid/repository/npm//private/a.tgz',
            'https://nexus.example.invalid/repository/npm\\..\\private/a.tgz',
            'https://nexus.example.invalid/repository/npm/a.tgz?access_token=SECRET',
            'https://nexus.example.invalid/repository/npm/a.tgz#secret',
            'https://nexus.example.invalid:bad/repository/npm/a.tgz',
            'https://nexus.example.invalid:0/repository/npm/a.tgz',
            'https://nexus.example.invalid:99999/repository/npm/a.tgz',
            'https://nexus.example.invalid/repository/npm/a.tgz\n',
            'https://nexus.example.invalid/repository/npm%2f../private.tgz',
            'https://nexus.example.invalid/repository/npm-other/a.tgz',
            'https://nexus.example.invalid.evil/repository/npm/a.tgz',
        )
        client=core.LiveDataClient(reg,timeout=1,batch_size=1,sleep_sec=0,use_system_proxy=False)
        for url in hostile:
            with self.subTest(url=url):
                self.assertFalse(client.registry_artifact_url_allowed(url), url)
                self.assertFalse(lockfile_allowed(reg,url), url)
        # Non-HTTP lock resolutions are handled by their own lockfile policies.
        self.assertTrue(lockfile_allowed(reg,'workspace:../local'))

    def test_sensitive_and_encoded_path_segments_not_exported(self):
        for url in (
            'https://user:pw@nexus.invalid/repository/abc123/npm?token=secret',
            'https://nexus.invalid/repository/%61piKey/npm',
            'https://nexus.invalid/repository/short-secret/npm',
            'https://nexus.invalid/repository/tenant42/npm',
            'https://nexus.invalid/repository/AbCdEf123=/npm',
        ):
            with self.subTest(url=url):
                data=json.dumps(_identity(url),sort_keys=True)
                for secret in ('user','pw','secret','apiKey','abc123','tenant42','AbCdEf123','token'):
                    self.assertNotIn(secret, data)
                self.assertIn('/repository/[redacted]/npm',data)

    def test_bad_registry_port_is_fail_closed(self):
        self.assertFalse(safe_registry_artifact_url('https://nexus.invalid:xyz/npm',
                                                   'https://nexus.invalid/npm/a.tgz'))

    def test_known_structural_failure_but_compatible_target_stays_visible(self):
        reg='https://nexus.invalid/npm'
        m={'versions': {'1.0.0': {'dist': {'tarball':reg+'/a.tgz'}},
                        '1.1.0': {'dist': {'tarball':reg+'/../private.tgz'}},
                        '1.2.0': {'dist': {'tarball':reg+'/b.tgz'}}}}
        diag=summarize_structural_candidates(reg,m,m['versions'],lambda u:safe_registry_artifact_url(reg,u),current='1.0.0')
        self.assertEqual(1,diag['acceptedUpgradeCandidates'])
        self.assertFalse(diag['allUpgradeCandidatesRejected'])
        self.assertNotEqual('NO_INSTALLABLE_ARTIFACT',no_target_diagnostic_code('no-target',diag))


class RedirectDoesNotContactForbiddenHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.disallowed_hits=0
        cls.allowed_hits=0
        class ForbiddenHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                cls.disallowed_hits+=1
                self.send_response(200);self.end_headers();self.wfile.write(b'leak')
        cls.forbidden = http.server.ThreadingHTTPServer(('127.0.0.1',0),ForbiddenHandler)
        cls.t_forbidden=threading.Thread(target=cls.forbidden.serve_forever,daemon=True)
        cls.t_forbidden.start()
        class SourceHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                cls.allowed_hits+=1
                if self.path.endswith('/foreign'):
                    target=f'http://127.0.0.1:{cls.forbidden.server_port}/outside'
                    self.send_response(302);self.send_header('Location',target);self.end_headers();return
                if self.path.endswith('/escape'):
                    self.send_response(302);self.send_header('Location','/not-allowed/other');self.end_headers();return
                if self.path.endswith('/badport'):
                    self.send_response(302);self.send_header('Location','http://127.0.0.1:nope/');self.end_headers();return
                if self.path.endswith('/loop'):
                    self.send_response(302);self.send_header('Location','/npm/loop');self.end_headers();return
                if self.path.endswith('/redirect'):
                    self.send_response(307);self.send_header('Location','/npm/good');self.end_headers();return
                if self.path.endswith('/good'):
                    self.send_response(206);self.send_header('Content-Length','1');self.end_headers();self.wfile.write(b'x');return
                self.send_response(404);self.end_headers()
        cls.source=http.server.ThreadingHTTPServer(('127.0.0.1',0),SourceHandler)
        cls.t_source=threading.Thread(target=cls.source.serve_forever,daemon=True)
        cls.t_source.start()
        cls.registry=f'http://127.0.0.1:{cls.source.server_port}/npm'
    @classmethod
    def tearDownClass(cls):
        for server,th in ((cls.source,cls.t_source),(cls.forbidden,cls.t_forbidden)):
            server.shutdown();server.server_close();th.join(timeout=3)

    def _probe(self,name):
        client=core.LiveDataClient(self.registry,timeout=3,batch_size=1,sleep_sec=0,use_system_proxy=False)
        # Non-draft mode: actual tiny range GET; never a fake installed tree.
        meta={'versions':{'1.1.0':{'dist':{'tarball':self.registry+'/'+name}}}}
        return client.registry_version_artifact('demo',meta,'1.1.0')

    def test_foreign_redirect_refused_before_request(self):
        before=self.disallowed_hits
        result=self._probe('foreign')
        self.assertEqual('foreign-registry-redirect',result['status'])
        self.assertEqual(before,self.disallowed_hits,'must never contact forbidden host')
        self.assertFalse(result.get('finalUrl'))

    def test_same_origin_outside_prefix_refused_before_request(self):
        before=self.allowed_hits
        result=self._probe('escape')
        self.assertEqual('foreign-registry-redirect',result['status'])
        self.assertEqual(before+1,self.allowed_hits,'must fetch only initial URL')

    def test_bad_redirect_port_fails_closed_without_exception(self):
        result=self._probe('badport')
        self.assertEqual('foreign-registry-redirect',result['status'])

    def test_same_prefix_redirect_can_be_verified(self):
        result=self._probe('redirect')
        self.assertEqual('available',result['status'])
        self.assertEqual(206,result['httpStatus'])

    def test_redirect_loop_is_bounded(self):
        result=self._probe('loop')
        self.assertEqual('redirect-limit-exceeded',result['status'])

    def test_http_404_preserves_missing_artifact_status(self):
        result=self._probe('absent')
        self.assertEqual('missing-artifact',result['status'])

class RegistryPromptSanitizationTests(unittest.TestCase):
    def test_prompt_never_renders_secret_userinfo_or_private_path(self):
        value='https://admin:hunter2@nexus.invalid/repository/abc123/npm?token=qwerty#fragment'
        sanitized=core._sanitize_registry_url(value)
        for raw in ('admin','hunter2','abc123','qwerty','fragment','token='):
            self.assertNotIn(raw,sanitized)
        self.assertEqual('https://nexus.invalid/repository/[redacted]/npm',sanitized)
    def test_public_registry_prompt_retains_origin(self):
        self.assertEqual('https://registry.npmjs.org',core._sanitize_registry_url('https://registry.npmjs.org'))
