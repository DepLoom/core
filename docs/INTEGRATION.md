# Using DepLoom Core in MCP

1. Verify the new Core release revision and its headless CI.
2. Point `DepLoom/mcp`'s `.gitmodules` at
   `https://github.com/DepLoom/core.git` and update the
   `upstream/deploom` gitlink to the exact committed Core revision.
3. Recompute the 133-file Core SHA-256 inventory in
   `DepLoom/mcp/release-manifest.json`; preserve schema and Skill hashes.
   The updated Core `peer_solver_transition.py` and
   `draft_input_identity.py` differ from the previous pin.
4. Run MCP's contract/target-assessment tests, stdio smoke, full CI matrix,
   sdist → wheel and installed-wheel smoke outside checkout.
5. Run a small **planning-only** fixture through MCP with
   `policies: {"sample-router": "required"}`; verify it returns an
   applicable Draft or an authentic blocker, never a false
   `INVALID_CURRENT_ENDPOINT`.
6. Freeze Core/MCP revisions, no-Skill setup and fixture evidence before
   comparing agent + MCP against a bare agent.

**Repository visibility:** If MCP is public and Core stays private,
`actions/checkout` in MCP cannot fetch the private submodule with its
ordinary repository-scoped `GITHUB_TOKEN`. Either make Core public or
configure a dedicated least-privileged read-only credential for this cross-repo
checkout, in compliance with the organization's security policy. Do not
publish a private Core's source through a public wheel by accident.

This repo contains no Desktop release workflow or automatic migration runner.
