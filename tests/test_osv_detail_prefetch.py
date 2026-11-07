"""Advisory prefetch retains exact evidence, failure and deadline semantics."""
import http.server
import json
import threading
import time
import unittest
from unittest.mock import patch
import dependency_live_roadmap_generator as core

class DisabledExternalEvidenceTests(unittest.TestCase):
    def test_policy_blocks_osv_queries_and_detail_before_network(self):
        client = object.__new__(core.LiveDataClient)
        with patch.dict("os.environ", {"DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "1"}):
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.query_osv_versions("example", ["1.0.0"])
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.fetch_osv_vuln("example")


    def test_approved_registry_source_is_used_without_osv_fallback(self):
        client = object.__new__(core.LiveDataClient)
        registry = "https://registry.example.invalid/npm"
        with patch.dict("os.environ", {"DEPLOOM_DRAFT_DISABLE_EXTERNAL_EVIDENCE": "1",
                                      "DEPLOOM_DRAFT_REGISTRY_ADVISORY_SOURCE": registry}), patch.object(
            client, "_query_registry_security_versions", side_effect=core.VulnerabilityEvidenceUnavailable
        ) as query:
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):
                client.query_osv_versions("example", ["1.0.0"])
            query.assert_called_once_with("example", ["1.0.0"], registry)


class OsvDetailsTests(unittest.TestCase):
    def setUp(self):
        self.seen=[];self.active=0;self.peak=0;self.lock=threading.Lock();owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                with owner.lock:
                    owner.seen.append(self.path);owner.active+=1;owner.peak=max(owner.peak,owner.active)
                try:
                    time.sleep(.20)
                    bad=self.path.endswith('/BAD')
                    body=json.dumps({'id':self.path.rsplit('/',1)[-1],'severity':[{'type':'CVSS_V3','score':'retained'}]}).encode()
                    self.send_response(503 if bad else 200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                    try:self.wfile.write(body)
                    except OSError:pass
                finally:
                    with owner.lock:owner.active-=1
        self.http=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        self.url=patch.object(core,'OSV_VULN',f'http://127.0.0.1:{self.http.server_port}/{{id}}');self.url.start()
        self.client=core.LiveDataClient('https://registry.example.invalid',timeout=3,batch_size=100,sleep_sec=0)
    def tearDown(self):
        self.url.stop();self.http.shutdown();self.http.server_close();self.thread.join();self.client.session.close()
    def test_unique_fresh_bodies_and_bounded_concurrency(self):
        ids=['A','B','C','D','E','A'];self.client._prefetch_osv_details(ids)
        self.assertEqual(set(self.client.vuln_detail_cache),set(ids));self.assertEqual(len(self.seen),5)
        self.assertGreater(self.peak,1);self.assertLessEqual(self.peak,4)
        self.assertEqual(self.client.fetch_osv_vuln('C')['severity'][0]['score'],'retained')
        self.client._prefetch_osv_details(ids);self.assertEqual(len(self.seen),5)
    def test_failure_does_not_publish_partial_or_empty_evidence(self):
        with self.assertRaises(core.VulnerabilityEvidenceUnavailable):self.client._prefetch_osv_details(['A','BAD'])
        self.assertEqual(self.client.vuln_detail_cache,{})
    def test_deadline_and_late_workers_cannot_mutate_parent(self):
        self.client.set_deadline(core.DeadlineClock(core.DRAFT_FINALIZE_RESERVE_SECONDS+.09))
        with self.assertRaises(core.DraftBudgetExceeded):self.client._prefetch_osv_details(['A','B'])
        time.sleep(.3);self.assertEqual(self.client.vuln_detail_cache,{})
    def test_query_batch_preserves_version_mapping_and_detail_order(self):
        response=unittest.mock.Mock()
        payload={'results':[{'vulns':[{'id':'B'},{'id':'A'}]},{}, {'vulns':[{'id':'A'}]}]}
        with patch.object(self.client.session,'post',return_value=response), patch.object(self.client,'_bounded_json',return_value=payload):
            result=self.client.query_osv_versions('demo',['1.0.0','2.0.0','3.0.0'])
        self.assertEqual([x['id'] for x in result['1.0.0']],['B','A'])
        self.assertEqual(result['2.0.0'],[])
        self.assertEqual([x['id'] for x in result['3.0.0']],['A'])
        self.assertEqual(sorted(self.seen),['/A','/B'])
    def test_query_failure_does_not_cache_clean_version(self):
        response=unittest.mock.Mock()
        with patch.object(self.client.session,'post',return_value=response), patch.object(self.client,'_bounded_json',return_value={'results':[{'vulns':[{'id':'A'},{'id':'BAD'}]}]}):
            with self.assertRaises(core.VulnerabilityEvidenceUnavailable):self.client.query_osv_versions('demo',['1.0.0'])
        self.assertEqual(self.client.osv_cache,{})
    def test_single_body_keeps_canonical_path(self):
        self.client._prefetch_osv_details(['A']);self.assertEqual(self.seen,[])
        self.assertEqual(self.client.fetch_osv_vuln('A')['id'],'A');self.assertEqual(len(self.seen),1)
if __name__=='__main__':unittest.main()
