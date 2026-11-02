# Standalone CLI generated output contract v1

Status: Core boundary implementation. MCP admission/current/checkpoint integration
and installed end-to-end acceptance are separate required steps.

The default source policy includes generated and ignored source. An operator may
explicitly select `DEPLOOM_SOURCE_SCOPE_MODE=standalone-js-cli-output-v1` for an
isolated standalone npm project. This separates `dist/` and `.tap/` from authored
inputs. A fingerprint under this policy is only an input identity. It does not
verify outputs. Generic complete-source verification refuses this policy.

`materialized_workspace_verifier.verify_current_workspace` additionally requires
`generated_output_spec`, schema 1 / `STANDALONE_JS_CLI_OUTPUT_V1`, with exact
`buildFiles`, `testFiles`, `emptyDirectories`, and SHA-256 identities of
`scripts/build.js`, the original `test` script and original `test:perf` script.
Commands must start with `npm test`, then `npm run test:perf`. Further independent
checks may follow, but cannot change the already captured output inventory.
No command, assertion, test collection or performance threshold is rewritten.

Before installation and immediately before the first project command, both output
roots must be absent. Existing output is rejected, never silently deleted. The
first successful command must produce all exact declared build files and all test
result files. The supported grammar is deliberately bounded:

- Flat `dist/<declared-file>` paths only; no extra build files.
- `.tap/processinfo/<canonical-lowercase-UUID>.json`, 1 through 128 files.
- `.tap/test-results/tests/<declared-original-test>.js.tap`, exact input test set.
- Optional recipe-declared `.tap/fixtures`, required to be empty after cleanup.
- At most 8 MiB per file and 64 MiB total; no automatic cap expansion.

Every directory and file is enumerated; unknown entries, case collisions,
symlinks, NTFS junctions/reparse points, hardlinks and unstable reads fail closed.
Processinfo content is hashed, not parsed or treated as executable authority.
Fresh stages cannot reuse old TAP files: some TAP modes can consult them to
select tests. UUIDs are not compared across independent executions.

The returned `generatedOutputObservation` binds the full inventory to source,
approved lock and dependency plan, command recipe, invocation, profile,
environment and toolchain. File hashes and physical identities are checked again
before/after later commands and at return. The native verifier separately requires
supervised process-tree closure. Deletion, replacement or byte changes invalidate
the observation. An expected binding is mandatory for `receipt_current`.

This is a non-reusable boundary observation, not a checkpoint, execution grant,
proof of arbitrary concurrent filesystem closure, or per-file writer attestation.
Outputs are excluded from authored-input comparison only under the explicit
profile; without the complete typed observation no verification may be accepted.
MCP must join the observation to its own host policy, independent final checks and
current/checkpoint/resume owners before exposing accepted route semantics.

Focused tests: `python -m unittest discover -s tests -p test_standalone_build_outputs.py -v`.
The fixture native commands validate source/output scope and supervision only;
their artificial TAP files are not evidence of any real project's correctness.
