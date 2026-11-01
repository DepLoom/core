"""Compare actual sealed source and prepared trees, not fake verifier success."""
import dataclasses,hashlib,json,shutil,stat,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from source_snapshot import verification_source_snapshot_scope
from artifact_integrity import build_artifact_tree_integrity
from resolved_dependency_state import ResolvedDependencyState,ResolvedDependencyStateError
from verification_source_closure import compare_materialized_source_origin,validate_materialized_source_closure,MaterializedSourceOriginError

class MaterializedOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.project=self.base/"source";self.project.mkdir()
        manifest={"name":"source-origin-unit","version":"1.0.0"}
        (self.project/"package.json").write_text(json.dumps(manifest)+"\n",encoding="utf-8")
        (self.project/"package-lock.json").write_text(json.dumps({"name":"source-origin-unit","version":"1.0.0","lockfileVersion":2,"packages":{"":manifest}})+"\n",encoding="utf-8")
        (self.project/"index.js").write_text("console.log('approved');\n",encoding="utf-8")
        for args in (["init","-q"],["add","--","package.json","package-lock.json","index.js"],["-c","user.name=DepLoom Test","-c","user.email=fixture@example.invalid","-c","commit.gpgSign=false","commit","-q","-m","frozen input"]):
            subprocess.run(["git","-C",str(self.project),*args],check=True,capture_output=True,timeout=10)
    def prepare(self,source,name="prepared",change=None):
        target=self.base/("prepared-"+name);shutil.copytree(source.root,target)
        for path in target.rglob("*"):
            if path.is_file():path.chmod(path.stat().st_mode|stat.S_IWUSR)
        if change:change(target)
        seal=build_artifact_tree_integrity(target,source_only=True)
        prepared=SimpleNamespace(workspace_root=target,project_relative=Path("."),source_closure_entries=seal.source_entries,source_closure_content_key=seal.source_content_key)
        lock=(target/"package-lock.json").read_bytes()
        state=ResolvedDependencyState("b"*64,"c"*64,"npm","package-lock.json",hashlib.sha256(lock).hexdigest(),"d"*64,"",lock)
        return prepared,state
    def test_equal_physical_source_and_prepared_seals(self):
        with verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as source:
            prepared,state=self.prepare(source)
            validate_materialized_source_closure(prepared,prepared.workspace_root)
            record=compare_materialized_source_origin(source,prepared,state)
            self.assertEqual(record["normalizedInputSourceKey"],record["preparedSourceContentKey"])
            self.assertFalse(record["fullAcceptance"]);self.assertEqual(record["inputSourceSnapshotKey"],source.key)
    def test_self_consistent_changed_source_config_extra_and_missing_rejected(self):
        changes={"source":lambda p:(p/"index.js").write_text("changed",encoding="utf-8"),
            "manifest":lambda p:(p/"package.json").write_text('{"name":"source-origin-unit","version":"2.0.0"}',encoding="utf-8"),
            "extra":lambda p:(p/"generated-config.json").write_text("{}",encoding="utf-8"),
            "missing":lambda p:(p/"index.js").unlink()}
        with verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as source:
            for name,change in changes.items():
                with self.subTest(name=name):
                    prepared,state=self.prepare(source,name,change)
                    validate_materialized_source_closure(prepared,prepared.workspace_root)
                    with self.assertRaisesRegex(MaterializedSourceOriginError,"SOURCE_ORIGIN_MISMATCH"):
                        compare_materialized_source_origin(source,prepared,state)
    def test_changed_lock_and_wrong_resolved_identity_rejected(self):
        with verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as source:
            prepared,state=self.prepare(source)
            with self.assertRaises(ResolvedDependencyStateError):
                compare_materialized_source_origin(source,prepared,dataclasses.replace(state,lockfile_hash="0"*64))
            p=prepared.workspace_root/"package-lock.json";p.write_bytes(p.read_bytes()+b" ")
            seal=build_artifact_tree_integrity(prepared.workspace_root,source_only=True)
            prepared.source_closure_entries=seal.source_entries;prepared.source_closure_content_key=seal.source_content_key
            lock=p.read_bytes();state=dataclasses.replace(state,lockfile_hash=hashlib.sha256(lock).hexdigest(),lockfile_bytes=lock)
            with self.assertRaisesRegex(MaterializedSourceOriginError,"SOURCE_ORIGIN_MISMATCH"):
                compare_materialized_source_origin(source,prepared,state)
    def test_ambiguous_paths_reparse_and_wrong_seal_unproven(self):
        with verification_source_snapshot_scope(self.project,timeout_seconds=15,strict_cleanup=True) as source:
            prepared,state=self.prepare(source)
            for row in ({"path":"../alias","kind":"directory"},{"path":"alias","kind":"symlink","target":"index.js"}):
                modified=SimpleNamespace(**vars(prepared));modified.source_closure_entries=(*prepared.source_closure_entries,row)
                with self.assertRaisesRegex(MaterializedSourceOriginError,"SOURCE_ORIGIN_UNPROVEN"):
                    compare_materialized_source_origin(source,modified,state)
            modified=SimpleNamespace(**vars(prepared));modified.source_closure_content_key="0"*64
            with self.assertRaisesRegex(MaterializedSourceOriginError,"SOURCE_ORIGIN_UNPROVEN"):
                compare_materialized_source_origin(source,modified,state)

if __name__=="__main__":unittest.main()
