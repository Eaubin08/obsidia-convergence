<#
.SYNOPSIS
    Clôture groupée des preuves disponibles sur le portable Obsidia.
.DESCRIPTION
    Une seule commande : vérifie le PC et le worktree isolé, exécute les
    régressions unifiées et candidates, revérifie la clé Windows existante,
    signe et revérifie un snapshot du code C278 live, produit un journal.
    N'exécute pas de test C278 du FIX, ne modifie pas le FIX, ne lance aucun
    serveur et n'accorde aucune autorité de release ou de mutation.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$machine = [Environment]::MachineName.ToUpperInvariant()
if ($machine -ne 'DESKTOP-Q5MD7J7') { throw "OBSIDIA_WRONG_PC:$machine" }

$runtime = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$repo = (Resolve-Path -LiteralPath (Join-Path $runtime '..\..')).Path
$fix = Join-Path $env:USERPROFILE '.codex\visualizations\2026\11\kx108_zero_vote_guard_fix'
$publicSha = '5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398'

if (-not (Test-Path -LiteralPath (Join-Path $repo '.git'))) {
    throw 'OBSIDIA_VERIFY_FROM_DEDICATED_GIT_WORKTREE_ONLY'
}
if (-not (Test-Path -LiteralPath $fix -PathType Container)) {
    throw 'OBSIDIA_PORTABLE_FIX_NOT_FOUND'
}
$changes = @(git -C $repo status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) {
    throw 'OBSIDIA_INTEGRATION_WORKTREE_NOT_CLEAN'
}
$fixHeadBefore = git --no-optional-locks -C $fix rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $fixHeadBefore -notmatch '^[0-9a-f]{40}$') {
    throw 'OBSIDIA_SOURCE_FIX_HEAD_NOT_AVAILABLE'
}
$fixStatusBefore = @(git --no-optional-locks -C $fix status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'OBSIDIA_SOURCE_FIX_STATUS_FAILED' }

$oldPythonPath = $env:PYTHONPATH
$downloads = Join-Path $env:USERPROFILE 'Downloads'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fffffff'
$log = Join-Path $downloads ("OBSIDIA_PORTABLE_GOVERNANCE_ONE_PASS_${timestamp}.log")
$report = Join-Path $downloads ("OBSIDIA_PORTABLE_GOVERNANCE_ONE_PASS_${timestamp}.json")
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stage = 'START'
$results = [ordered]@{
    schema = 'OBSIDIA_PORTABLE_GOVERNANCE_ONE_PASS_V1'
    machine = $machine
    source_pc = 'DESKTOP-Q5MD7J7_PORTABLE'
    fixed_pc = 'DESKTOP-SDOG0EL_NOT_TOUCHED'
    integration_head = (git -C $repo rev-parse HEAD)
    source_head_before = $fixHeadBefore
    source_head_after = $null
    runtime_regression_pass = $false
    candidate_regression_pass = $false
    machine_rsa_interop_pass = $false
    live_c278_source_snapshot_signed = $false
    source_worktree_unchanged = 'NOT_CERTIFIED_BY_GIT_METADATA_ALONE'
    source_git_head_and_status_stable = $false
    integration_worktree_clean_after = $false
    test_process_attested = $false
    sandbox_import_origin_attested = $false
    machine_enrollment_approved = $false
    release_authorized = $false
    kx108_authority = 'UNCHANGED'
    functional_c278_live_runner = 'HOLD_NOT_EXECUTED'
    stage = 'START'
    verdict = 'HOLD'
}

try {
    $env:PYTHONPATH = "$runtime;$runtime\scripts"
    Write-Host '[1/4] Tests complets du runtime unifie (environnement de test local)'
    $stage = 'RUNTIME_TESTS'
    & py -3 -B -c 'import cryptography' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'CRYPTOGRAPHY_DEPENDENCY_REQUIRED' }
    # Windows PowerShell 5.1 traite parfois la sortie stderr de Python comme
    # une erreur PowerShell, même lorsque le processus termine avec code 0.
    $ErrorActionPreference = 'Continue'
    $testText = & py -3 -B -m unittest discover -s (Join-Path $runtime 'tests\integration') -p 'test_*stdlib_v1.py' -q 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    [System.IO.File]::WriteAllText($log, (($testText | Out-String) + [Environment]::NewLine), $utf8)
    if ($rc -ne 0) {
        $testText | Select-Object -Last 25 | ForEach-Object { Write-Host $_ }
        throw "RUNTIME_INTEGRATION_TESTS_HOLD_$rc"
    }
    $summary = ($testText | Out-String)
    $match = [regex]::Match($summary, 'Ran\s+(\d+)\s+tests')
    if (-not $match.Success -or [int]$match.Groups[1].Value -lt 160) {
        throw 'RUNTIME_TEST_COUNT_UNEXPECTED'
    }
    $results.runtime_regression_pass = $true
    Write-Host "RUNTIME_TESTS_PASS=$($match.Groups[1].Value)"

    Write-Host '[2/4] Tests de contrat G1/G2 (pas d exécution de production)'
    $stage = 'CANDIDATE_TESTS'
    $candidate = Join-Path $repo 'candidate\g1_g2\tests'
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
        throw 'CANDIDATE_TESTS_MISSING'
    }
    $ErrorActionPreference = 'Continue'
    $candidateText = & py -3 -B -m pytest -q -p no:cacheprovider $candidate 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    [System.IO.File]::AppendAllText($log, (($candidateText | Out-String) + [Environment]::NewLine), $utf8)
    if ($rc -ne 0) {
        $candidateText | Select-Object -Last 25 | ForEach-Object { Write-Host $_ }
        throw "CANDIDATE_G1_G2_TESTS_HOLD_$rc"
    }
    $results.candidate_regression_pass = $true
    $candidateText | Select-Object -Last 2 | ForEach-Object { Write-Host $_ }

    Write-Host '[3/4] Cle Windows du portable : signature RSA croisee Python'
    $stage = 'MACHINE_RSA'
    $interop = Join-Path $PSScriptRoot 'verify_obsidure_machine_rsa_interop_windows_v1.ps1'
    & $interop -ExpectedPublicSha256 $publicSha
    if (-not $?) { throw 'MACHINE_RSA_INTEROP_HOLD' }
    $results.machine_rsa_interop_pass = $true

    Write-Host '[4/4] Snapshot reel des sources C278 signe et reverifie'
    $stage = 'C278_LIVE_SOURCE_SNAPSHOT'
    $signer = Join-Path $PSScriptRoot 'verify_c278_portable_snapshot_windows_v1.ps1'
    & $signer
    if (-not $?) { throw 'C278_SNAPSHOT_SIGNING_OR_VERIFICATION_HOLD' }
    $results.live_c278_source_snapshot_signed = $true

    $fixHeadAfter = git --no-optional-locks -C $fix rev-parse HEAD
    $fixStatusAfter = @(git --no-optional-locks -C $fix status --porcelain --untracked-files=normal)
    if ($LASTEXITCODE -ne 0 -or $fixHeadAfter -cne $fixHeadBefore -or
        (($fixStatusAfter -join "`n") -cne ($fixStatusBefore -join "`n"))) {
        throw 'SOURCE_FIX_CHANGED_DURING_ONE_PASS'
    }
    $integrationStatusAfter = @(git -C $repo status --porcelain --untracked-files=normal)
    if ($LASTEXITCODE -ne 0 -or $integrationStatusAfter.Count -gt 0) {
        throw 'INTEGRATION_WORKTREE_CHANGED_DURING_ONE_PASS'
    }
    $results.source_git_head_and_status_stable = $true
    $results.integration_worktree_clean_after = $true
    $results.source_head_after = $fixHeadAfter
    $results.verdict = 'PORTABLE_EVIDENCE_READY_WITH_C278_TEST_PROVENANCE_HOLD'
    $results.stage = 'DONE'
    Write-Host 'OBSIDIA_PORTABLE_ONE_PASS_PASS=True' -ForegroundColor Green
}
catch {
    $results.stage = $stage
    $results.verdict = 'HOLD'
    Write-Host "OBSIDIA_PORTABLE_ONE_PASS_HOLD=$($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    $ErrorActionPreference = 'Stop'
    $env:PYTHONPATH = $oldPythonPath
    $json = $results | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($report, ($json + [Environment]::NewLine), $utf8)
    Write-Host "EVIDENCE_REPORT=$report"
    Write-Host "TEST_LOG=$log"
    Write-Host 'C278_HISTORICAL_TEST_PROVENANCE=HOLD'
    Write-Host 'KX108_AUTHORITY=UNCHANGED'
    Write-Host 'RELEASE=HOLD'
}
