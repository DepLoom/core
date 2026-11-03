# Core 0.1.1

This release integrates the explicit-version objective and scoped partial-Draft
guards, resolver preflight observations, finite coupled-choice helpers, source
and dependency identities, typed standalone output/input transport and bounded
verification/recovery helpers used by MCP. A Draft remains a proposal, not an
installed migration or full-tree compatibility proof.

The current helpers preserve source/assignment/proof identities and distinguish
resolver, materialization, checks and current versus historical evidence.
Timeout, missing evidence and infrastructure failure do not prove incompatibility.
These library helpers do not grant host execution authority; MCP maintains its
separate operator registration and capability boundary.

- [Resolver preflight](DRAFT_NPM_PREFLIGHT.md)
- [Standalone output contract](STANDALONE_OUTPUT_CONTRACT_V1.md)
- [Platform archive resources](NPM_PLATFORM_ARCHIVE_RESOURCE_V1.md)
- [Historical npm identities](NPM_HISTORICAL_IDENTITIES_V1.md)
- [Unchanged v2 aliases](NPM_V2_UNCHANGED_ALIASES_V1.md)

Native current-workspace, typed output and V2 exact-environment execution use
the declared Windows guaranteed-tree profile. Linux CI covers planning, portable
model/identity contracts and fail-closed negative boundaries; its best-effort
process-group supervisor does not establish a verified execution checkpoint.

Package version 0.1.1 is distinct from the retained upstream engine VERSION
identifier. Exact Core commit and content hashes identify a bundled runtime.
This release does not claim whole-workspace solving, universal execution support,
security-policy attainment or agent speedup.
