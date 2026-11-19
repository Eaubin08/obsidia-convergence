<#
.SYNOPSIS
    G4J : signe une fixture WAL C2 totalement synthétique avec la clé
    Windows existante du portable, puis vérifie via Python.
.DESCRIPTION
    Aucun certificat créé/exporté, aucune source historique modifiée.
    La signature ne prouve ni origine d'un réel runner, ni HumanApproval.
#>
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
if ($machine -ne 'DESKTOP-Q5MD7J7') {
    throw "G4J_WRONG_PC:$machine"
}
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4J_WORKTREE_NOT_FOUND'
}
$realHead = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $realHead -cne $ExpectedSourceHead) {
    throw 'G4J_SOURCE_HEAD_MISMATCH'
}
$changes = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) {
    throw 'G4J_WORKTREE_NOT_CLEAN'
}

$subject = "CN=OBSIDIA-OBSIDURE-$machine"
$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -eq $subject })
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'G4J_LOCAL_CERTIFICATE_NOT_AVAILABLE'
}
$cert = $certs[0]
$der = $cert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $pin = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}
if ($pin -cne $ExpectedPublicSha256) {
    throw 'G4J_PUBLIC_CERT_PIN_MISMATCH'
}

$proposalFile = Join-Path $env:USERPROFILE (
    "Downloads\OBSIDURE_PUBLIC_IDENTITY_$machine.json"
)
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'G4J_PUBLIC_ENROLLMENT_PROPOSAL_MISSING'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -cne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -cne $machine -or
    $proposal.public_certificate_sha256 -cne $pin -or
    $proposal.public_certificate_der_base64 -cne ([Convert]::ToBase64String($der))) {
    throw 'G4J_PUBLIC_PROPOSAL_CERT_BINDING_INVALID'
}

$generator = Join-Path $PSScriptRoot 'prepare_g4j_wal_synthetic_fixture_v1.py'
$verifier = Join-Path $PSScriptRoot 'verify_g4j_wal_receipt_v1.py'
if (-not (Test-Path -LiteralPath $generator -PathType Leaf) -or
    -not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'G4J_PYTHON_TOOLS_NOT_FOUND'
}

$fixtureRoot = Join-Path $env:TEMP (
    'obsidia-g4j-' + [Guid]::NewGuid().ToString('N')
)
try {
    $json = & py -3 -B -X utf8 $generator `
        --root $fixtureRoot `
        --machine $machine `
        --pin $pin `
        --source-head $ExpectedSourceHead
    if ($LASTEXITCODE -ne 0) {
        throw 'G4J_SYNTHETIC_FIXTURE_HOLD'
    }
    $fixture = $json | ConvertFrom-Json
    if ($fixture.repo_root -cne $fixtureRoot) {
        throw 'G4J_SYNTHETIC_FIXTURE_ROOT_MISMATCH'
    }
    $message = [Convert]::FromBase64String($fixture.signing_message_base64)
    $private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($null -eq $private) {
        throw 'G4J_PRIVATE_KEY_INACCESSIBLE'
    }
    try {
        if ($private.KeySize -lt 3072) {
            throw 'G4J_RSA_KEY_TOO_SMALL'
        }
        $signature = $private.SignData(
            $message,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally {
        $private.Dispose()
    }

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
    if ($rc -ne 0) {
        throw "G4J_WINDOWS_PYTHON_RSA_HOLD_$rc"
    }
}
finally {
    # Cible exacte et éphémère, créée avec un GUID uniquement pour ce test.
    if ((Test-Path -LiteralPath $fixtureRoot) -and
        (Split-Path -Leaf $fixtureRoot) -match '^obsidia-g4j-[0-9a-f]{32}$' -and
        (Split-Path -Parent $fixtureRoot) -eq $env:TEMP) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
