# Unchanged npm lock v2 aliases

Install name/path, canonical package name/version and incoming alias spec are
separate identities. A legacy record can encode `npm:canonical@1.2.3` while its
packages view stores canonical name and the exact `1.2.3` version. This typed
comparison does not rewrite original lock bytes or replace installation paths
with canonical names. Scoped canonical names use an unambiguous final @ split.

Only aliases already present in the original v2 lock are admitted. Both views
must agree on canonical identity, resolved/SRI, flags and requirements. The Core
compiler binds exact packages and raw legacy record digests plus complete
incoming alias edges; before/after maps must match. Incoming ranges need not be
identical to a pinned version string, but must explicitly name the canonical
package and contain that pinned version. New, changed, renamed, orphaned or
removed aliases and incoming-edge changes fail closed.

The MCP scope owner reuses its unchanged v3 alias join for same-format v2 locks,
additionally compares raw legacy alias subtrees and retains raw legacy records.
The normalized alias version exists only in internal identity validation. No
change in declared target or transitive scope is inferred. Physical observation
still checks actual installed canonical manifests and edges. Archive/SRI, host,
platform selectors, case/path and source guards remain unchanged.
