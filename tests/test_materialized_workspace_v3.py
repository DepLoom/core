"""Actual offline npm/Node v3 checks; inherited guards include nonzero/source drift."""
import json,unittest
from pathlib import Path
import importlib.util
_spec=importlib.util.spec_from_file_location('_v3_fixture_'+Path(__file__).stem,Path(__file__).with_name('test_materialized_workspace_verifier.py'))
fixtures=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(fixtures)
from resolved_dependency_state import compile_npm_dependency_obligations
from source_snapshot import source_snapshot_fingerprint

class CurrentV3WorkspaceTests(fixtures.CurrentWorkspaceVerificationTests):
    def setUp(self):
        super().setUp();path=self.project/'package-lock.json';lock=json.loads(path.read_bytes());lock['lockfileVersion']=3;raw=json.dumps(lock).encode();path.write_bytes(raw)
        self.plan=compile_npm_dependency_obligations(raw,raw,exact_targets={},changed_instances=[],delta_digest='a'*64,scope_digest='b'*64)
        self.key=source_snapshot_fingerprint(self.project)

if __name__=='__main__':unittest.main()
