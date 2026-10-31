# Draft npm resolver preflight

Draft's static optimization model covers declared package peers and environment
constraints over extracted finite domains. It does not model npm's nested
transitive instances or package placement. `constraintModel` in `plan.json` and
`result.json` states this boundary explicitly, even for `DRAFT_READY`.

An optional resolver preflight checks the full proposed root assignment through
npm in a separate fresh-lock directory:

```powershell
python dependency_live_roadmap_generator.py --settings settings.json `
  --draft-baseline --draft-deadline-seconds 180 `
  --draft-npm-preflight --draft-npm-preflight-seconds 60 `
  --draft-npm-preflight-cache .cache/npm --draft-npm-preflight-offline
```

The preflight keeps all existing root names and pins proposed/retained versions.
It preserves other manifest fields and project `.npmrc`, never edits source or
its lock, and explicitly enforces strict peers, engine checks, scripts disabled,
no force, no legacy peers, and ordinary hoisted placement. Saved cache is used
only when offline is requested. Cache misses are unknown evidence. Network
registry selection comes from the same Draft execution context.

The per-project cap is at most60 seconds and is also clamped to the remaining
absolute Draft budget; it never renews the planning deadline. The existing
process supervisor owns and terminates the child tree. Early partial publication
never launches this optional final preflight.

`packageManagerValidation.status` is distinct from mathematical feasibility:

- `NOT_RUN`: the default static-only Draft path.
- `RESOLUTION_PASSED`: npm exited successfully and the generated lock contains
  the exact complete root assignment. Installation, lifecycle, source checks and
  runtime have not run; authority remains `PLANNING_ONLY`/`NOT_VERIFIED` and
  compatibility remains `UNKNOWN`.
- `RESOLUTION_FAILED`: npm reported a resolution/engine failure. Readiness becomes
  `DRAFT_PARTIAL`; the prompt says `PM_VALIDATION_FAILED` and forbids applying
  that vector. Proposals remain available as diagnostic evidence.
- `UNKNOWN`: missing cache, timeout, unsupported topology/runtime, source changes
  or missing/mismatched lock evidence. Readiness becomes `DRAFT_PARTIAL` and the
  prompt says `PM_VALIDATION_UNKNOWN`, not a proved conflict.

Workspaces and non-npm package-manager declarations currently fail closed as
unsupported. This helper does not replace their existing authoritative verifier.

Per-project output and receipts are stored under the run's `package-manager/`
folder. Receipts bind source manifest/lock/config hashes, assignment, runtime
binary/entrypoint hashes and resolver options. Raw logs may contain private
registry/path information and must not be published without sanitization.

No preflight failure becomes a solver nogood: `learningAllowed=false`. A terminal
npm placement conflict describes one environment and resolver attempt; it is not
proof of global UNSAT or a context-free incompatibility between package names.
No transitive overrides, source repair, alternate versions or root additions are
automatically introduced by this feature.
