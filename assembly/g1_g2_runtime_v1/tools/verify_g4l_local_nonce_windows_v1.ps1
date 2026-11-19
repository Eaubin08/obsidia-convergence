<# G4L : UNE fixture synthétique ; deux processus Python ; replay local refusé. #>
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPublicSha256,

    [Parameter(Mandatory = $true)]
    [string]$WorktreePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceHead
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$machine = [Environment]::MachineName.ToUpperInvariant()
if ($machine -cne 'DESKTOP-Q5MD7J7') { throw 'G4L_WRONG_PC' }
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4L_WORKTREE_NOT_FOUND'
}
$actual = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -cne $ExpectedSourceHead) {
    throw 'G4L_SOURCE_HEAD_MISMATCH'
}
$dirty = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
    throw 'G4L_WORKTREE_NOT_CLEAN'
}

$subject = 'CN=OBSIDIA-OBSIDURE-' + $machine
$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -ceq $subject })
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'G4L_LOCAL_MACHINE_IDENTITY_UNAVAILABLE'
}
$cert = $certs[0]
$der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $pin = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($pin -cne $ExpectedPublicSha256) { throw 'G4L_CERTIFICATE_PIN_MISMATCH' }

$proposalFile = Join-Path $env:USERPROFILE (
    'Downloads\OBSIDURE_PUBLIC_IDENTITY_' + $machine + '.json'
)
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'G4L_PUBLIC_CERTIFICATE_PROPOSAL_MISSING'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -cne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -cne $machine -or
    $proposal.public_certificate_sha256 -cne $pin -or
    $proposal.public_certificate_der_base64 -cne ([Convert]::ToBase64String($der))) {
    throw 'G4L_PUBLIC_CERTIFICATE_PROPOSAL_MISMATCH'
}

$generator = Join-Path $PSScriptRoot 'prepare_g4k_synthetic_subprocess_v1.py'
$checker = Join-Path $PSScriptRoot 'verify_g4l_local_nonce_v1.py'
if (-not (Test-Path -LiteralPath $generator -PathType Leaf) -or
    -not (Test-Path -LiteralPath $checker -PathType Leaf)) {
    throw 'G4L_PYTHON_TOOLS_MISSING'
}
$fixtureRoot = Join-Path $env:TEMP ('obsidia-g4l-' + [Guid]::NewGuid().ToString('N'))
try {
    $fixtureJson = & py -3 -B -X utf8 $generator `
        --root $fixtureRoot `
        --machine $machine `
        --pin $pin `
        --source-head $ExpectedSourceHead
    if ($LASTEXITCODE -ne 0) { throw 'G4L_SYNTHETIC_FIXTURE_HOLD' }
    $fixture = $fixtureJson | ConvertFrom-Json
    if ($fixture.repo_root -cne $fixtureRoot -or
        $fixture.synthetic_process_observed -cne $true -or
        $fixture.process_origin_attested -cne $false) {
        throw 'G4L_SYNTHETIC_FIXTURE_INVALID'
    }

    $message = [Convert]::FromBase64String($fixture.signing_message_base64)
    $private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($null -eq $private) { throw 'G4L_PRIVATE_KEY_UNAVAILABLE' }
    try {
        if ($private.KeySize -lt 3072) { throw 'G4L_RSA_KEY_TOO_SMALL' }
        $signature = $private.SignData(
            $message,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally { $private.Dispose() }

    $data = [ordered]@{
        wal_dir = $fixture.wal_dir
        repo_root = $fixture.repo_root
        intent_id = $fixture.intent_id
        receipt = [ordered]@{
            payload = $fixture.payload
            signature_base64 = [Convert]::ToBase64String($signature)
        }
        public_certificate_der_base64 = [Convert]::ToBase64String($der)
        pinned_certificate_sha256 = $pin
        expected_machine_id = $machine
    }
    $inputJson = $data | ConvertTo-Json -Compress -Depth 12

    Write-Host '[G4L/1] RESERVATION LOCALE SIGNATURE VERIFIEE'
    $first = $inputJson | & py -3 -B -X utf8 $checker --reserve
    $firstCode = $LASTEXITCODE
    $first | ForEach-Object { Write-Host $_ }
    if ($firstCode -ne 0) { throw 'G4L_FIRST_RESERVATION_HOLD' }

    Write-Host '[G4L/2] SECOND PROCESSUS : REPLAY REFUSE'
    $second = $inputJson | & py -3 -B -X utf8 $checker --deny-replay
    $secondCode = $LASTEXITCODE
    $second | ForEach-Object { Write-Host $_ }
    if ($secondCode -ne 0) { throw 'G4L_REPLAY_DENIAL_HOLD' }
}
finally {
    if ((Test-Path -LiteralPath $fixtureRoot) -and
        (Split-Path -Leaf $fixtureRoot) -match '^obsidia-g4l-[0-9a-f]{32}$' -and
        (Split-Path -Parent $fixtureRoot) -eq $env:TEMP) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
