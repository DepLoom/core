# Releasing this component

This procedure releases **this repository only**. It never releases Desktop or a
project whose dependencies are being migrated. Use Python 3.12 or 3.13, Git and
the existing GitHub SSH identity. No local PAT, `gh auth login`, browser upload or
global proxy change is required. GitHub Actions uses its short-lived built-in
repository token; only the final publishing job has `contents: write`.

## Normal patch release

First commit, review and merge the intended source changes into `main`. The
launcher deliberately refuses to stage arbitrary dirty or untracked files.
Then, from the repository root in PowerShell:

```powershell
git switch main
git pull --ff-only
# MCP only: initialize the already reviewed Core pin.
git submodule update --init --recursive

# Read-only local inspection; no version edit, push or API request.
.\push-github-branch-and-tag.ps1 -Python python -DryRun

# Create the next package patch, then atomically push main + annotated tag.
.\push-github-branch-and-tag.ps1 -Python python -NewRelease
```

If HTTPS is blocked but SSH is available, initialize MCP with the following
process-local URL rewrite instead (no global Git/proxy settings are changed):

```powershell
git -c 'url.git@github.com:.insteadOf=https://github.com/' submodule update --init --recursive
```

Omit the `git submodule` command in Core. `-Python` may name an existing virtual
environment interpreter. Package versioning is separate from Core's retained
engine `VERSION`: the launcher does not rewrite that engine identifier. MCP
synchronizes `pyproject.toml`, `__version__` and the manifest's `mcpVersion`; it
never silently changes the Core gitlink, Skill, migration scope or README.
A Core pin update must be committed and reviewed before an MCP release.

The launcher requires `main`, the exact public SSH `origin`, a synchronized
source commit and a clean worktree. It commits only version-bearing files. It
never uses a destructive rollback, force push or tag replacement. New edits made
during the release cause a stop and remain intact.

## What happens automatically

The tag starts the **Component release** workflow. It waits for the existing full
`main` CI on the exact version commit instead of running that unit matrix twice.
The workflow checks repository/tag/version/source identity, sanitizes tracked
source, builds wheel and sdist, installs the wheel outside the checkout, rebuilds
from sdist and checks the rebuilt wheel. MCP also requires its packaged P1/D1
correctness and proxy gates at the same source revision.

Draft releases are discovered through the authenticated release list and then
addressed by release ID; the public tag lookup cannot discover a draft.

Only after these gates pass does it create a draft release, upload the wheel,
sdist, `RELEASE-EVIDENCE.json` and `SHA256SUMS.txt`, verify every server-side
SHA-256/size, and publish. No PyPI upload or new credentials are configured.
A green release does not expand the supported migration matrix or replace real
project acceptance. These tools never replace an existing tag or different published asset bytes;
they do not configure additional repository-admin tag rulesets.

## Completion and retries

`PUSHED_AWAITING_WORKFLOW` means the Git refs were verified over SSH, but workflow discovery and completion have not
yet been observed; it does **not** claim that the packages are public. Follow the printed
workflow URL and check the final publishing job and four release assets.
Optionally wait through the public GitHub API:

```powershell
.\push-github-branch-and-tag.ps1 -Python python -Tag vX.Y.Z -WaitMinutes 20
```

Use the **same actual tag printed by the first attempt**, not the example above.
If local HTTPS/API access is unavailable, use the Actions URL; the script does
not change proxy settings. SSH can still trigger the complete server workflow.

Durable state lives in ignored `.component-release/`. Repeating the command on
the same source resumes the same attempt without another patch bump. A native
process lock prevents concurrent launchers; remote tag object/target and main
ancestry are rechecked before recording a successful push. Do not
delete that state while a release is pending. If publication alone failed, use
Actions **Re-run failed jobs**: it reuses the original qualified artifact bundle.
Do not rerun all jobs to replace previously uploaded binary bytes. The publish job downloads the exact artifact ID from that run and verifies its
bundle digest and the independently bound checksum-manifest hash. The publisher
accepts matching existing assets, uploads missing draft assets, and rejects any
name, size or digest conflict; it never uses `--clobber`.

If CI found a source defect, preserve the failed tag, fix and merge the source,
then run with `-NewRelease` for a new patch. If source or remote state changes
unexpectedly, inspect the recorded commit/tag and worktree before continuing.
Never move an already published tag to make a failed attempt look successful.
