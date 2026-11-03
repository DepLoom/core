#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Tag = '',
    [string]$Python = 'python',
    [switch]$NewRelease,
    [switch]$DryRun,
    [ValidateRange(0,30)][int]$WaitMinutes = 0
)
$ErrorActionPreference = 'Stop'
$commandArgs = @('-B', (Join-Path $PSScriptRoot 'scripts/component_release.py'))
if ($Tag) { $commandArgs += @('--tag', $Tag) }
if ($NewRelease) { $commandArgs += '--new-release' }
if ($DryRun) { $commandArgs += '--dry-run' }
if ($WaitMinutes) { $commandArgs += @('--wait-minutes', [string]$WaitMinutes) }
& $Python @commandArgs
if ($LASTEXITCODE -ne 0) { throw ('Component release stopped: EXIT_{0}' -f $LASTEXITCODE) }
