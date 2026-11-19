<# G4K: processus Python synthétique observé, puis RSA Windows, HOLD strict. #>
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
if ($machine -cne 'DESKTOP-Q5MD7J7') { throw 'G4K_WRONG_MACHINE' }
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4K_WORKTREE_NOT_FOUND'
}
$actualHead = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -cne $ExpectedSourceHead) {
    throw 'G4K_SOURCE_HEAD_MISMATCH'
}
$dirty = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
    throw 'G4K_WORKTREE_NOT_CLEAN'
}

$subject = 'CN=OBSIDIA-OBSIDURE-' + $machine
$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -ceq $subject })
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'G4K_MACHINE_IDENTITY_NOT_AVAILABLE'
}
$cert = $certs[0]
$der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$hash = [System.Security.Cryptography.SHA256]::Create()
try {
    $pin = [BitConverter]::ToString($hash.ComputeHash($der)).Replace('-', '').ToLowerInvariant()
}
finally { $hash.Dispose() }
if ($pin -cne $ExpectedPublicSha256) { throw 'G4K_CERTIFICATE_PIN_MISMATCH' }
$proposalFile = Join-Path $env:USERPROFILE (
    'Downloads\OBSIDURE_PUBLIC_IDENTITY_' + $machine + '.json'
)
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'G4K_PUBLIC_CERTIFICATE_PROPOSAL_NOT_FOUND'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -cne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -cne $machine -or
    $proposal.public_certificate_sha256 -cne $pin -or
    $proposal.public_certificate_der_base64 -cne ([Convert]::ToBase64String($der))) {
    throw 'G4K_CERTIFICATE_PROPOSAL_BINDING_FAILED'
}

$generator = Join-Path $PSScriptRoot 'prepare_g4k_synthetic_subprocess_v1.py'
$verifier = Join-Path $PSScriptRoot 'verify_g4k_synthetic_runner_v1.py'
if (-not (Test-Path -LiteralPath $generator -PathType Leaf) -or
    -not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'G4K_TOOLS_NOT_FOUND'
}
$fixtureRoot = Join-Path $env:TEMP ('obsidia-g4k-' + [Guid]::NewGuid().ToString('N'))
try {
    $json = & py -3 -B -X utf8 $generator `
        --root $fixtureRoot `
        --machine $machine `
        --pin $pin `
        --source-head $ExpectedSourceHead
    if ($LASTEXITCODE -ne 0) { throw 'G4K_SYNTHETIC_SUBPROCESS_FAILED' }
    $fixture = $json | ConvertFrom-Json
    if ($fixture.repo_root -cne $fixtureRoot -or
        $fixture.synthetic_process_observed -cne $true -or
        $fixture.process_origin_attested -cne $false) {
        throw 'G4K_SYNTHETIC_FIXTURE_INVALID'
    }

    $message = [Convert]::FromBase64String($fixture.signing_message_base64)
    $private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($null -eq $private) { throw 'G4K_PRIVATE_KEY_UNAVAILABLE' }
    try {
        if ($private.KeySize -lt 3072) { throw 'G4K_RSA_KEY_TOO_SMALL' }
        $signature = $private.SignData(
            $message,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally { $private.Dispose() }

    $inputData = [ordered]@{
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
    $verificationJson = $inputData | ConvertTo-Json -Compress -Depth 12
    $output = $verificationJson | & py -3 -B -X utf8 $verifier
    $rc = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($rc -ne 0) { throw "G4K_WAL_RUNNER_VERIFY_HOLD_$rc" }
}
finally {
    if ((Test-Path -LiteralPath $fixtureRoot) -and
        (Split-Path -Leaf $fixtureRoot) -match '^obsidia-g4k-[0-9a-f]{32}$' -and
        (Split-Path -Parent $fixtureRoot) -eq $env:TEMP) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
