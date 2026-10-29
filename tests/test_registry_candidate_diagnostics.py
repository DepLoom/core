"""Core #3: bounded, actionable registry artifact rejection diagnostics.

Synthetic metadata and localhost only; no npm installs, OSV, GitHub or LLM.
The original Core registry admission guard remains the authority for eligibility.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

import dependency_live_roadmap_generator as core
from registry_candidate_diagnostics import (
    MAX_SAMPLES,
    REJECTION_CODES,
    no_target_diagnostic_code,
    summarize_structural_candidates,
    with_observed_physical_probes,
)


def _meta(urls):
    return {"name": "sample", "versions": {
        version: {"dist": ({"tarball": url} if url is not None else {})}
        for version, url in urls.items()
    }}


def _client(registry):
    return core.LiveDataClient(
        registry, timeout=3, batch_size=4, sleep_sec=0,
        use_system_proxy=False,
    )


def _health():
    return core.ProjectHealth(
        project="sample", status="yellow", status_rank=1,
        total=1, lag_ok_12m=0, lag_bad_12m=1, lag_ok_pct=0.0,
        critical=1, high=0, moderate=0, low=0, unknown=0,
        reason="synthetic pending upgrade",
        lag_unknown=0, lag_needed_for_yellow=1,
        yellow_plan_required=1, yellow_projected_lag_ok=0,
        yellow_projected_lag_pct=0.0, yellow_plan_shortfall=1,
    )


def _row(evidence):
    return core.DependencyRow(
        project="sample", package_dir="/tmp/sample", name="sample", kind="runtime",
        requested_spec="1.0.0", current_version="1.0.0",
        current_source="package-lock.json", latest_version="1.2.0",
        current_vulns="C:1, H:0", min_no_critical="—", min_no_high="—",
        min_no_vuln="—", min_lag_12m="—", min_lag_9m="—",
        min_lag_6m="—", min_lag_3m="—", group=1, reason="synthetic", notes="",
        draft_scan_state="done", registry_candidate_diagnostics=evidence,
    )


class RegistryCandidateDiagnosticsTests(unittest.TestCase):
    def test_matching_registry_does_not_change_existing_admission(self):
        registry = "https://registry.npmjs.org/"
        c = _client(registry)
        urls = {"1.0.0": "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz",
                "1.2.0": "https://registry.npmjs.org/sample/-/sample-1.2.0.tgz"}
        meta = _meta(urls)
        versions = list(urls)
        before = c.registry_structural_candidates(meta, versions)
        evidence = summarize_structural_candidates(c.registry, meta, versions,
                                                   c.registry_artifact_url_allowed, current="1.0.0")
        after = c.registry_structural_candidates(meta, versions)
        self.assertEqual(before, after)
        self.assertEqual(versions, after[0])
        self.assertEqual(0, evidence["rejected"])
        self.assertEqual(1, evidence["acceptedUpgradeCandidates"])
        self.assertFalse(evidence["allUpgradeCandidatesRejected"])
        self.assertIsNone(no_target_diagnostic_code("proposed", evidence))

    def test_public_packument_pointed_at_local_registry_explains_no_target(self):
        registry = "http://127.0.0.1:42358/frozen/"
        c = _client(registry)
        urls = {"1.0.0": "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz",
                "1.2.0": "https://registry.npmjs.org/sample/-/sample-1.2.0.tgz"}
        meta = _meta(urls)
        structural, notes_before = c.registry_structural_candidates(meta, urls)
        evidence = summarize_structural_candidates(c.registry, meta, urls,
                                                   c.registry_artifact_url_allowed, current="1.0.0")
        self.assertEqual([], structural)
        self.assertEqual(2, len(notes_before))
        self.assertEqual({"FOREIGN_TARBALL_ORIGIN": 2}, evidence["rejectionCounts"])
        self.assertTrue(evidence["allUpgradeCandidatesRejected"])
        self.assertEqual("NO_INSTALLABLE_ARTIFACT", no_target_diagnostic_code("no-target", evidence))
        self.assertEqual("https://registry.npmjs.org", evidence["rejectedArtifactOrigins"][0])
        self.assertEqual("http://127.0.0.1:42358", evidence["configuredRegistry"]["origin"])
        self.assertEqual("/[redacted]", evidence["configuredRegistry"]["pathPrefix"])

    def test_registry_path_prefix_missing_tarball_and_malformed(self):
        registry = "https://nexus.example.invalid/repository/npm/"
        c = _client(registry)
        urls = {
            "1.0.0": "https://nexus.example.invalid/repository/npm/sample/1.0.0.tgz",
            "1.1.0": "https://nexus.example.invalid/repository/other/sample/1.1.0.tgz",
            "1.2.0": None,
            "1.3.0": "file:///etc/passwd",
        }
        evidence = summarize_structural_candidates(c.registry, _meta(urls), urls,
                                                   c.registry_artifact_url_allowed, current="1.0.0")
        self.assertEqual(1, evidence["accepted"])
        self.assertEqual({"BAD_REGISTRY_PATH": 2, "MISSING_DIST_TARBALL": 1},
                         evidence["rejectionCounts"])
        self.assertEqual("NO_INSTALLABLE_ARTIFACT", no_target_diagnostic_code("no-target", evidence))
        self.assertFalse(evidence["physicalProbe"]["observed"])
        self.assertIn("BAD_REGISTRY_PATH", REJECTION_CODES)

    def test_conservative_when_some_candidate_remains(self):
        reg = "https://nexus.example.invalid/repo"
        c = _client(reg)
        urls = {"1.0.0": f"{reg}/sample/1.0.0.tgz",
                "1.2.0": f"{reg}/sample/1.2.0.tgz",
                "1.3.0": "https://foreign.invalid/sample/1.3.0.tgz"}
        diagnostic = summarize_structural_candidates(reg, _meta(urls), urls,
                                                     c.registry_artifact_url_allowed, current="1.0.0")
        self.assertEqual(1, diagnostic["acceptedUpgradeCandidates"])
        self.assertFalse(diagnostic["allUpgradeCandidatesRejected"])
        self.assertEqual("UNRESOLVED_TARGET_CONSTRAINT_OR_POLICY",
                         no_target_diagnostic_code("no-target", diagnostic))
        self.assertIsNone(no_target_diagnostic_code("blocked", diagnostic))
        self.assertEqual("CANDIDATE_CAP", no_target_diagnostic_code("candidate-search-truncated", diagnostic))

    def test_bounded_diagnostics_never_disclose_credentials_or_urls(self):
        registry = "https://admin:secret@registry.internal:443/repository/secretTokenValue/npm?token=top-secret#frag"
        c = _client(registry)
        urls = {f"1.{i}.0": f"https://bob:pwd@evil.internal/path/package-{i}.tgz?access_token=xyz"
                for i in range(50)}
        diag = summarize_structural_candidates(registry, _meta(urls), urls,
                                               c.registry_artifact_url_allowed, current="1.0.0")
        raw = json.dumps(diag)
        for secret in ("admin:", "secret@", "secretTokenValue", "top-secret", "pwd@", "access_token", "?token="):
            self.assertNotIn(secret, raw)
        self.assertLessEqual(len(diag["rejectionSamples"]), MAX_SAMPLES)
        self.assertLessEqual(len(diag["rejectedArtifactOrigins"]), MAX_SAMPLES)
        self.assertEqual(50, diag["rejected"])

    def test_publication_carries_bounded_codes_with_no_solver_reclassification(self):
        reg = "http://127.0.0.1:49000/frozen"
        c = _client(reg)
        meta = _meta({"1.0.0": "https://registry.npmjs.org/sample/1.0.0.tgz",
                      "1.2.0": "https://registry.npmjs.org/sample/1.2.0.tgz"})
        evidence = summarize_structural_candidates(reg, meta, ["1.0.0", "1.2.0"],
                                                   c.registry_artifact_url_allowed, current="1.0.0")
        row = _row(evidence)
        # Reproduce the exact legacy fallback from a frozen registry with no
        # structurally allowed tarballs; this is metadata KNOWN, not an OSV
        # outage or a missing packument.
        row.latest_version = c.latest_installable_version(
            "sample", meta, current="1.0.0",
        )
        self.assertIn("не найден installable tarball", row.latest_version)
        self.assertTrue(core._row_metadata_known(row))
        self.assertEqual("no-target", core._draft_row_status(row, core._draft_target_for_major(row)))
        plan = core.build_draft_plan({"sample": [row]}, {}, {"sample": _health()})
        pub = plan["proposals"][0]["rows"][0]
        self.assertEqual("no-target", pub["status"])
        self.assertEqual("NO_INSTALLABLE_ARTIFACT", pub["noTargetDiagnosticCode"])
        self.assertEqual(evidence, pub["registryCandidateDiagnostics"])
        self.assertEqual(1, plan["counts"]["no-installable-artifact"])
        self.assertEqual(1, plan["registryDiagnostics"]["noInstallableArtifactRows"])
        self.assertEqual(2, plan["registryDiagnostics"]["rejectedVersions"])
        self.assertEqual(0, plan["counts"]["proposed"])
        self.assertEqual(evidence, core.row_json(row)["registry_candidate_diagnostics"])

    def test_unassessed_registry_does_not_create_false_diagnostic(self):
        row = _row({})
        row.latest_version = "registry unavailable"
        row.current_vulns = "unknown"
        row.draft_unknown = "registry-failed"
        result = core.build_draft_plan({"sample": [row]}, {}, {"sample": _health()})
        pub = result["proposals"][0]["rows"][0]
        self.assertEqual("unknown-metadata", pub["status"])
        self.assertNotIn("noTargetDiagnosticCode", pub)
        self.assertNotIn("registryCandidateDiagnostics", pub)
        self.assertEqual(0, result["registryDiagnostics"]["noInstallableArtifactRows"])

    def test_physical_evidence_does_not_create_false_success(self):
        base = {"examined": 2, "accepted": 2, "allUpgradeCandidatesRejected": False}
        observed = {"1.0.0": {"status": "current-installed"},
                    "1.1.0": {"status": "planning-only"},
                    "1.2.0": {"status": "missing-artifact"},
                    "1.3.0": {"status": "empty-artifact"},
                    "1.4.0": {"status": "foreign-registry-redirect"}}
        result = with_observed_physical_probes(base, observed, current="1.0.0")
        self.assertEqual({"FOREIGN_TARBALL_ORIGIN": 1, "HTTP_ARTIFACT_UNAVAILABLE": 2},
                         result["physicalProbe"]["failureCounts"])
        self.assertFalse(result["physicalProbe"]["unprobed"])
        self.assertFalse(result["allUpgradeCandidatesRejected"])
        self.assertNotEqual("NO_INSTALLABLE_ARTIFACT", no_target_diagnostic_code("no-target", result))
        just_planning = with_observed_physical_probes(base, {"1.1.0": {"status": "planning-only"}})
        self.assertTrue(just_planning["physicalProbe"]["unprobed"])


class RegistryArtifactHttpFixtureTests(unittest.TestCase):
    """A genuinely served local artifact, not an external mocked HTTP call."""

    @classmethod
    def setUpClass(cls):
        cls.payload = b"test-package-tarball-byte-content" * 9
        cls.requested = []
        payload = cls.payload
        requested = cls.requested
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                requested.append(self.path)
                if self.path.endswith("missing.tgz"):
                    self.send_response(404); self.end_headers(); return
                if self.path.endswith("redirect.tgz"):
                    self.send_response(302);self.send_header("Location", "/outside/package.tgz");self.end_headers();return
                if self.path == "/outside/package.tgz":
                    self.send_response(200);self.end_headers();self.wfile.write(payload);return
                if self.path != "/npm/sample/-/sample-1.1.0.tgz":
                    self.send_response(404); self.end_headers(); return
                is_range = self.headers.get("Range") == "bytes=0-0"
                body = payload[:1] if is_range else payload
                self.send_response(206 if is_range else 200)
                if is_range:self.send_header("Content-Range", f"bytes 0-0/{len(payload)}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers();self.wfile.write(body)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.registry = f"http://127.0.0.1:{cls.server.server_port}/npm"
        cls.baseurl = cls.registry + "/sample/-/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.worker.join(3)

    def test_valid_path_reads_real_tarball_with_matching_sri(self):
        target = self.baseurl + "sample-1.1.0.tgz"
        c = _client(self.registry)
        meta = _meta({"1.1.0": target})
        eligible, _ = c.registry_structural_candidates(meta, ["1.1.0"])
        self.assertEqual(["1.1.0"], eligible)
        evidence = c.registry_version_artifact("sample", meta, "1.1.0")
        self.assertEqual("available", evidence["status"])
        self.assertIn("/npm/sample/-/sample-1.1.0.tgz", self.requested)
        response = c.session.get(target, timeout=3)
        self.assertEqual(200, response.status_code)
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(self.payload).digest()).decode()
        observed = "sha512-" + base64.b64encode(hashlib.sha512(response.content).digest()).decode()
        self.assertEqual(integrity, observed)
        self.assertNotEqual(integrity, "sha512-" + base64.b64encode(hashlib.sha512(b"tampered").digest()).decode())

    def test_404_and_foreign_redirect_are_not_available(self):
        c = _client(self.registry)
        urls = {"1.1.0": self.baseurl + "missing.tgz",
                "1.2.0": self.baseurl + "redirect.tgz"}
        meta = _meta(urls)
        self.assertEqual(["1.1.0", "1.2.0"], c.registry_structural_candidates(meta, urls)[0])
        self.assertEqual("missing-artifact", c.registry_version_artifact("sample", meta, "1.1.0")["status"])
        self.assertEqual("foreign-registry-redirect", c.registry_version_artifact("sample", meta, "1.2.0")["status"])
        diagnostic = summarize_structural_candidates(c.registry, meta, urls,
                                                     c.registry_artifact_url_allowed, current="1.0.0")
        observed = with_observed_physical_probes(diagnostic, {v: c.registry_artifact_cache[("sample", v)] for v in urls}, current="1.0.0")
        self.assertEqual({"FOREIGN_TARBALL_ORIGIN": 1, "HTTP_ARTIFACT_UNAVAILABLE": 1},
                         observed["physicalProbe"]["failureCounts"])


if __name__ == "__main__":
    unittest.main()
