# Headless Core regression-test boundary

The original Desktop monorepo contained 130+ top-level test modules and more
than 2,000 tests across desktop, physical migration, storage and verification
workflows. The independent **headless planning Core** deliberately does not
own that entire product surface.

## Required checks on every Core PR

The [headless Core CI](../.github/workflows/ci.yml) runs every
`tests/test_*.py` module in this repository on:
- Ubuntu + Python 3.12
- Ubuntu + Python 3.13
- Windows + Python 3.12

This is a **single selected contract suite**, not a filtered invocation that
silently ignores newly added files. Regression failures block the PR.

The first extraction had six focused test modules. The added tests cover:

| Component | Examples |
| --- | --- |
| Finite-domain solver | Oracle, Z3, exact assignment, monotonicity and fallback |
| Compatibility and transition | Current/target peer relationships, cross-group cohorts, learner nogoods, mandatory updates |
| Planning intent | Explicit mutable scope, `required`, deferrals, decision/health target selection |
| Draft publication | Run-scoped `plan.json`/`result.json`, immutable input hashes, honest partial status, candidate cap/truncation, Yellow/Green, target security UNKNOWN and goal summaries |
| Registry metadata | Cache identity, credential boundaries, local test registry, concurrent access |
| Workspace | Topology, package-manager control files, glob expansion, input coverage |
| Provenance | Source/lock identity, plans/entrypoints, evidence references and replayable inputs |
| Infrastructure | Atomic progress, cached constraints, non-destructive source handling |

The tests are copied from the former repository where they already existed,
except for an explicit reduction of five Desktop-release/UI assertions from
`test_peer_compatibility_solver.py`. The removal is intentional: release
scripts, Electron UI and legacy branching tests belong to the historical
Desktop project, not to this headless engine.

## What CI does not prove

- Full cross-workspace joint dependency assignment: Core reports this
  limitation, but does not yet solve a monorepo jointly.
- Physical npm/yarn installability, generated source migration quality,
  browser/runtime correctness or an installed-tree security verdict.
- Registry/OSV snapshot determinism without frozen external evidence.
- A causal agent speedup or any effect of the optional Skill.

Those checks belong to the MCP consumer, the separately controlled migration
benchmark and real-project integration, not to this sub-minute gate.

## Ownership rule

Add a new test to Core when it guards a public Draft planning contract or the
runtime consumed by MCP. Put **consumer projection/stdio/wheel tests** in MCP.
Leave **Desktop GUI, physical installation, release and historical execution
tests** in the old repository. A Core change that modifies a shared contract
requires updating the MCP pinned revision only after its own CI is green.

Before benchmarking, run a separate end-to-end synthetic `required`
planning request via the **installed** MCP wheel to verify that the release
pin, subprocess, full blueprint and compact preserve the same semantics.
