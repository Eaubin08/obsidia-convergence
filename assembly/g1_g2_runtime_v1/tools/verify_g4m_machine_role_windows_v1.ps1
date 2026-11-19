<# G4M : propose une identité par PC, ne valide aucun responsable ni rôle. #>
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
if ($machine -cne 'DESKTOP-Q5MD7J7') { throw 'G4M_WRONG_PC' }
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4M_WORKTREE_NOT_FOUND'
}
$actualHead = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -cne $ExpectedSourceHead) {
    throw 'G4M_SOURCE_HEAD_MISMATCH'
}
$changes = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) {
    throw 'G4M_WORKTREE_NOT_CLEAN'
}

$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object {
    $_.Subject -ceq ('CN=OBSIDIA-OBSIDURE-' + $machine)
})
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'G4M_LOCAL_CERTIFICATE_NOT_AVAILABLE'
}
$cert = $certs[0]
$der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$hash = [System.Security.Cryptography.SHA256]::Create()
try { $pin = [BitConverter]::ToString($hash.ComputeHash($der)).Replace('-', '').ToLowerInvariant() }
finally { $hash.Dispose() }
if ($pin -cne $ExpectedPublicSha256) { throw 'G4M_CERT_PIN_MISMATCH' }
$cert64 = [Convert]::ToBase64String($der)

$proposalFile = Join-Path $env:USERPROFILE (
    'Downloads\OBSIDURE_PUBLIC_IDENTITY_' + $machine + '.json'
)
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'G4M_PUBLIC_CERT_PROPOSAL_NOT_FOUND'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -cne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -cne $machine -or
    $proposal.public_certificate_sha256 -cne $pin -or
    $proposal.public_certificate_der_base64 -cne $cert64) {
    throw 'G4M_EXISTING_PUBLIC_PROPOSAL_CHANGED'
}

$generator = Join-Path $PSScriptRoot 'prepare_g4k_synthetic_subprocess_v1.py'
$verifier = Join-Path $PSScriptRoot 'verify_g4m_machine_role_proposal_v1.py'
if (-not (Test-Path -LiteralPath $generator -PathType Leaf) -or
    -not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'G4M_PYTHON_TOOLS_MISSING'
}
$fixtureRoot = Join-Path $env:TEMP ('obsidia-g4m-' + [Guid]::NewGuid().ToString('N'))
try {
    $json = & py -3 -B -X utf8 $generator `
        --root $fixtureRoot `
        --machine $machine `
        --pin $pin `
        --source-head $ExpectedSourceHead
    if ($LASTEXITCODE -ne 0) { throw 'G4M_SYNTHETIC_FIXTURE_HOLD' }
    $fixture = $json | ConvertFrom-Json
    if ($fixture.repo_root -cne $fixtureRoot -or
        $fixture.synthetic_process_observed -cne $true -or
        $fixture.process_origin_attested -cne $false) {
        throw 'G4M_SYNTHETIC_FIXTURE_INVALID'
    }

    $message = [Convert]::FromBase64String($fixture.signing_message_base64)
    $private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($null -eq $private) { throw 'G4M_PRIVATE_KEY_NOT_AVAILABLE' }
    try {
        if ($private.KeySize -lt 3072) { throw 'G4M_RSA_KEY_TOO_SMALL' }
        $signature = $private.SignData(
            $message,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally { $private.Dispose() }

    # Un enregistrement PUBLIC par machine, aucune identité créée sur le fixe.
    $proposedRole = @('OBSIDURE_TEST_EVIDENCE_PRODUCER')
    $portableEntry = [ordered]@{
        machine_id = 'DESKTOP-Q5MD7J7'
        enrollment_state = 'ENROLLED_AWAITING_REVIEW'
        public_certificate_der_base64 = $cert64
        public_certificate_sha256 = $pin
        responsible_refs = @()
        proposed_roles = $proposedRole
        enrollment_review_ref = $null
        revocation_ref = $null
    }
    $fixedEntry = [ordered]@{
        machine_id = 'DESKTOP-SDOG0EL'
        enrollment_state = 'PLANNED'
        public_certificate_der_base64 = $null
        public_certificate_sha256 = $null
        responsible_refs = @()
        proposed_roles = $proposedRole
        enrollment_review_ref = $null
        revocation_ref = $null
    }
    $registry = [ordered]@{
        schema = 'OBSIDIA_OBSIDURE_MACHINE_IDENTITY_REGISTRY_V1'
        decision_authority = 'KX108_ONLY'
        trust_model = 'PER_MACHINE_INDEPENDENT_ASYMMETRIC'
        machine_identities = @($portableEntry, $fixedEntry)
    }

    $inputData = [ordered]@{
        registry = $registry
        wal_dir = $fixture.wal_dir
        repo_root = $fixture.repo_root
        intent_id = $fixture.intent_id
        receipt = [ordered]@{
            payload = $fixture.payload
            signature_base64 = [Convert]::ToBase64String($signature)
        }
        public_certificate_der_base64 = $cert64
        expected_public_certificate_sha256 = $pin
        expected_machine_id = $machine
    }
    $inputJson = $inputData | ConvertTo-Json -Compress -Depth 16
    $output = $inputJson | & py -3 -B -X utf8 $verifier
    $exit = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exit -ne 0) { throw 'G4M_ROLE_PROPOSAL_VERIFY_HOLD' }
}
finally {
    if ((Test-Path -LiteralPath $fixtureRoot) -and
        (Split-Path -Leaf $fixtureRoot) -match '^obsidia-g4m-[0-9a-f]{32}$' -and
        (Split-Path -Parent $fixtureRoot) -eq $env:TEMP) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
