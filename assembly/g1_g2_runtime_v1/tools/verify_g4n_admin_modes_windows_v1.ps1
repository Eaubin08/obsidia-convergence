<# G4N : préflight isolé. Aucun certificat Windows ou dépôt source modifié. #>
param(
    [Parameter(Mandatory = $true)]
    [string]$WorktreePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceHead
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::MachineName.ToUpperInvariant() -cne 'DESKTOP-Q5MD7J7') {
    throw 'G4N_WRONG_PC'
}
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4N_WORKTREE_NOT_FOUND'
}
$actualHead = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -cne $ExpectedSourceHead) {
    throw 'G4N_SOURCE_HEAD_MISMATCH'
}
$changes = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) {
    throw 'G4N_WORKTREE_NOT_CLEAN'
}
$root = Join-Path $WorktreePath 'assembly\g1_g2_runtime_v1'
$tool = Join-Path $root 'tools\verify_g4n_admin_modes_v1.py'
if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
    throw 'G4N_VERIFIER_NOT_FOUND'
}
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $root
    $out = & py -3 -B -X utf8 $tool
    $exit = $LASTEXITCODE
    $out | ForEach-Object { Write-Host $_ }
    if ($exit -ne 0) { throw 'G4N_FOUNDER_TEAM_CONTRACT_HOLD' }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
