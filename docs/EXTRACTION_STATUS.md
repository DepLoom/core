# Extraction status

Core was imported into the independent `DepLoom/core` repository from
`AlexanderLevenskikh/deploom:extract/headless-core-bootstrap-20261028`.
The initial import commit has the **identical Git tree** to source staging
commit `f45e50b92f22afb51335a36dad4e752251386abd`.
The original implementation root was kept unchanged.

## What was extracted

- 133 Python/runtime resources from the already pinned MCP Core inventory
  (including the canonical `VERSION`, config schemas and locale files).
- A small standalone Python distribution.
- Focused synthetic Z3, decision-contract, semantic-input and transition tests.
- CI limited to Linux/Python 3.12+3.13 and Windows/Python 3.12.

No Electron app, Desktop test suite, npm installation pipeline or migration
benchmark is part of this repository. The runtime set has not yet been pruned
to the minimal import closure.

## Changes compared with previous MCP-pinned Core

- `peer_solver_transition.py`: `USER_BASELINE_REQUIRED_UPDATE` constraints
  apply to the final solver decision, not to the all-current transition
  endpoint. Real peer constraints and final mandatory update remain enforced.
- `draft_input_identity.py`: Windows settings paths normalize to canonical
  case-insensitive workspace identity; focused tests also handle Windows
  pathname representation correctly.

These changes were verified by the standalone headless CI on the staging branch
and by the initial independent-repository CI.

## Pending integration

The MCP release inventory currently pins the historical Core SHA; it must be
updated to `DepLoom/core` and a new exact revision **before** treating any
MCP experiment as using this extracted Core. Do not silently mix versions.

See [integration instructions](INTEGRATION.md).
