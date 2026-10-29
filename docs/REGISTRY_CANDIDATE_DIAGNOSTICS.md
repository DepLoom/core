# Registry candidate diagnostics (Core issue #3)

This additive evidence explains registry artifact rejection in a **planning-only** DepLoom Draft. It does not change the existing `LiveDataClient.registry_artifact_url_allowed` admission predicate, physical artifact probes, Z3 solver, target, policy, or authoritative security evaluation.

## Published structures

- `plan.json.registryDiagnostics` — bounded aggregate counts: `examinedVersions`, `rejectedVersions`, `rejectionCounts`, `noInstallableArtifactRows`.
- `plan.json.proposals[].rows[].registryCandidateDiagnostics` — one package's observed structural evidence, with accepted/rejected upgrade counts, reasons, up to four version examples, safe registry origin and path prefix, and summaries of *already-executed* physical probes.
- `plan.json.proposals[].rows[].noTargetDiagnosticCode` — extra diagnosis for statuses `no-target` or `candidate-search-truncated`. The original row `status` and `reason` are preserved unchanged.
- `dependency-roadmap.json` rows also carry `registry_candidate_diagnostics` via the existing `row_json` serialization.

`registryCandidateDiagnostics` is absent for a row whose registry metadata was not successfully examined. An absent diagnostic must **not** be interpreted as zero rejected versions.

## Stable codes

| Code | Evidence | Meaning |
| --- | --- | --- |
| `MISSING_DIST_TARBALL` | Structural packument check | Version metadata has no `dist.tarball`. |
| `FOREIGN_TARBALL_ORIGIN` | Core's unchanged origin/path guard rejected URL or already-observed redirect | Artifact is outside the configured registry's origin. |
| `BAD_REGISTRY_PATH` | Core's unchanged guard rejected the URL | Invalid artifact URL, malformed authority or URL path outside the configured registry prefix. |
| `HTTP_ARTIFACT_UNAVAILABLE` | Already-observed physical GET probe only | Exact artifact gave HTTP 404/410 or an empty response. |
| `NO_INSTALLABLE_ARTIFACT` | A targetless Draft row with **all examined upgrade candidates** rejected structurally | There was no *structurally eligible* upgrade in this scanned universe. Does not prove universal absence in any registry. |
| `NO_PUBLISHED_UPGRADE_CANDIDATE` | Targetless row; no examined newer-version candidate | No newer version appeared in that scanned universe. |
| `UNRESOLVED_TARGET_CONSTRAINT_OR_POLICY` | Targetless row; at least one structural upgrade candidate remains | Do not blame the registry. Review peer, engine, policy, evidence and solver results separately. |
| `CANDIDATE_CAP` | Existing `candidate-search-truncated` status | A bounded evidence search; not a registry-origin rejection or OSV outage. |

`FOREIGN_TARBALL_ORIGIN`, `BAD_REGISTRY_PATH` and `MISSING_DIST_TARBALL` are **diagnostic classifications** of URLs that the existing Core guard already rejected. They cannot make a version eligible.

## Privacy, identity and proof boundaries

No new diagnostic records full `dist.tarball` URLs, credentials, query parameters, URL fragments or authorization headers. Registry/foreign-origin identities omit userinfo and remove suspicious path segments. `metadataRequestBase` is based on configured registry, explicitly tagged `CONFIGURATION_NOT_HTTP_TRACE`; it is **not** proof of which network endpoint actually responded.

`physicalProbe.unprobed=true` means no physical artifact check was observed; `planning-only` is never counted as an HTTP success. The Draft does not download artifacts to verify integrity and never claims installation or runtime compatibility. The real package manager must still enforce actual tarball integrity during installation.

The new per-package structural counters are defined over the exact `versions_from_current(..., max_candidates=0)` universe at the canonical analysis step. Existing candidate search caps, user-approved majors, peer/engine checks, exclusions and authoritative solver verdicts are **not** re-evaluated by this diagnostic.

If the standalone Core changes need to appear in the MCP compact projection, MCP must **explicitly repin** this Core and implement a separate backward-compatible projection change. This PR changes only Core, not its pinned consumer.

## Tests

```sh
python -m unittest tests/test_registry_candidate_diagnostics.py -v
python -m unittest discover -s tests -p "test_*.py" -v
```

Local regression fixtures use publicly synthetic metadata and localhost HTTP, including ranged probes, 404, redirect outside registry prefix, and an independently checked SHA-512 SRI; **no npm install** and no network call to OSV or a private Nexus is needed.
