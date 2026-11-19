<#
.SYNOPSIS
    Snapshot signé du code C278 du FIX portable avec la clé RSA existante.
.DESCRIPTION
    Fige les SHA des trois sources déjà observées puis les recontrôle avant
    de sauvegarder une preuve signée PUBLIQUE dans Downloads. Ne lance PAS
    de test C278 historique, ne touche PAS au FIX et n'ouvre aucune autorité.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$machine = [Environment]::MachineName.ToUpperInvariant()
if ($machine -ne 'DESKTOP-Q5MD7J7') { throw 'C278_SNAPSHOT_WRONG_MACHINE' }
$expectedSha = '5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398'
$subject = "CN=OBSIDIA-OBSIDURE-$machine"
$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -eq $subject })
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'C278_SNAPSHOT_CERTIFICATE_NOT_ENROLLED'
}
$cert = $certs[0]
$der = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($digest -cne $expectedSha) { throw 'C278_SNAPSHOT_PUBLIC_CERTIFICATE_PIN_MISMATCH' }

$proposalFile = Join-Path $env:USERPROFILE ("Downloads\OBSIDURE_PUBLIC_IDENTITY_$machine.json")
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'C278_SNAPSHOT_PUBLIC_ENROLLMENT_PROPOSAL_MISSING'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -ne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -ne $machine -or
    $proposal.public_certificate_sha256 -cne $expectedSha -or
    $proposal.public_certificate_der_base64 -cne ([Convert]::ToBase64String($der))) {
    throw 'C278_SNAPSHOT_PUBLIC_PROPOSAL_DOES_NOT_MATCH_EXISTING_KEY'
}

$helper = Join-Path $PSScriptRoot 'sign_and_verify_c278_source_portable_v1.py'
$preparedText = & py -3 -B -X utf8 $helper --prepare
if ($LASTEXITCODE -ne 0) { throw "C278_SNAPSHOT_PREPARE_HOLD:$preparedText" }
$prepared = $preparedText | ConvertFrom-Json
if ($prepared.status -ne 'READY_FOR_LOCAL_KEY_SIGNING') {
    throw 'C278_SNAPSHOT_PREPARED_STATUS_INVALID'
}
$messageBytes = [Convert]::FromBase64String($prepared.message_base64)
$private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($null -eq $private) { throw 'C278_SNAPSHOT_PRIVATE_KEY_UNAVAILABLE' }
try {
    if ($private.KeySize -lt 3072) { throw 'C278_SNAPSHOT_RSA_KEY_TOO_SMALL' }
    $signature = $private.SignData(
        $messageBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
}
finally { $private.Dispose() }

$envelope = [ordered]@{
    payload = $prepared.payload
    message_base64 = $prepared.message_base64
    signature_base64 = [Convert]::ToBase64String($signature)
    public_certificate_der_base64 = [Convert]::ToBase64String($der)
}
$json = $envelope | ConvertTo-Json -Compress -Depth 12
$verifiedText = $json | & py -3 -B -X utf8 $helper --verify
if ($LASTEXITCODE -ne 0) { throw "C278_SNAPSHOT_SIGNATURE_OR_SOURCE_HOLD:$verifiedText" }
$verified = $verifiedText | ConvertFrom-Json
if ($verified.status -ne 'C278_SOURCE_SNAPSHOT_RSA_MATCH_NO_TEST_PROVENANCE' -or
    $verified.machine_signature_verified -ne $true -or
    $verified.source_hashes_match -ne $true -or
    $verified.test_process_attested -ne $false -or
    $verified.release_authorized -ne $false) {
    throw 'C278_SNAPSHOT_VERIFICATION_STATUS_INVALID'
}

# Seule persistance : preuve publique hors des dépôts, jamais clé privée.
$filename = 'OBSIDURE_C278_SOURCE_SNAPSHOT_' + $machine + '_' +
    (Get-Date -Format 'yyyyMMdd_HHmmss_fffffff') + '.json'
$destination = Join-Path (Join-Path $env:USERPROFILE 'Downloads') $filename
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stream = [System.IO.File]::Open($destination, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try {
    $raw = $utf8.GetBytes($json + [Environment]::NewLine)
    $stream.Write($raw, 0, $raw.Length)
}
finally { $stream.Dispose() }

Write-Host 'C278_SOURCE_SNAPSHOT_RSA_WINDOWS_PASS=True'
Write-Host "SOURCE_GIT_HEAD=$($verified.source_git_head)"
Write-Host "SIGNED_PUBLIC_SNAPSHOT=$destination"
Write-Host 'TEST_PROCESS_ATTESTED=False'
Write-Host 'TEST_ISOLATION_CERTIFIED=False'
Write-Host 'ENROLLMENT_APPROVED=False'
Write-Host 'PRIVATE_KEY_EXPORTED=False'
Write-Host 'KX108_AUTHORITY=UNCHANGED'
Write-Host 'RELEASE=HOLD'
