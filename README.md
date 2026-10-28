# DepLoom Core

**Headless, evidence-aware dependency upgrade planning for JavaScript projects.**

DepLoom Core proposes bounded dependency-version assignments, evaluates npm peer
constraints through a Z3-backed solver, and preserves reasons, policy state and
missing evidence. The result is a **Draft plan** — not an installed, verified
migration.

Core is designed to be used without the former Electron/Desktop application.
[DepLoom MCP](https://github.com/DepLoom/mcp) exposes the planner to coding
agents and transforms its results into a compact, structured Upgrade Blueprint.

## What Core provides

- Dependency-version candidates within explicitly approved major lines and
  user-selected mutable scope.
- Distinct objectives for minimum changes needed to meet health policy versus
  newer compatible candidates in approved version lines.
- Explicit `pinned` / `advisory` target authority and explanations of known
  peer conflicts, blockers, deferred work and unknown security evidence.
- Source/workspace input coverage and semantic input fingerprints to help
  identify stale plans.
- A deterministic static solver under fixed inputs — **not** a claim that
  agent edits, npm resolution, registry state or runtime behavior are deterministic.

A Draft remains `PLANNING_ONLY`, `NOT_VERIFIED`. Project checks, npm install,
installed-tree audit and runtime acceptance remain separate responsibilities.
The current planner covers selected manifests; it does **not** solve an entire
multi-workspace graph jointly.

## Local development

Python **3.12 or 3.13** is supported for this package.

```sh
python -m venv .venv
python -m pip install -e .
python dependency_live_roadmap_generator.py --help
python -m unittest discover -s tests -p "test_required_planner.py" -v
```

The independent [lightweight CI](.github/workflows/ci.yml) runs a curated,
headless planner regression suite on Linux and Windows. See the
[testing boundary](docs/TESTING.md) for coverage and exclusions.
It does not run Electron, Desktop, npm migration benchmarks or the historical
monorepo test suite.

## Architecture and scope

This first extraction keeps the **133-file headless runtime inventory**
previously bundled in MCP, with stable module names for compatibility.
It is an operational split and a focused test split, **not yet a minimal
import-closure refactor**. Further shrinking should follow measured import
dependencies and regression coverage, rather than deleting modules by name.

The required-update transition regression is fixed here: `required` applies
to the **final** solver assignment, not the original state before upgrading;
genuine peer constraints still constrain transition cohorts.

- [Decision contract](docs/DRAFT_DECISION_CONTRACT.md)
- [Extraction status](docs/EXTRACTION_STATUS.md)
- [MCP integration instructions](docs/INTEGRATION.md)
- [No-Skill agent A/B protocol](docs/AB_NO_SKILL_PROTOCOL.md)

## Repository map

| Repository | Purpose |
| --- | --- |
| **[DepLoom/core](https://github.com/DepLoom/core)** | Headless dependency decision engine |
| **[DepLoom/mcp](https://github.com/DepLoom/mcp)** | MCP adapter, Blueprint projection and optional Skill |
| [AlexanderLevenskikh/deploom](https://github.com/AlexanderLevenskikh/deploom) | Historical Desktop/monorepo implementation |

## Evidence and limitations

Early diagnostic comparisons found no functional advantage from the full Skill
on one small React Router migration pair. Those studies do not establish
whether the solver-backed Blueprint helps agents make better upgrade decisions
on complex dependency graphs. The next experiment isolates **agent + MCP
(without Skill)** against a bare agent with matching tasks and quality gates.
See the protocol above; no speedup is claimed.
