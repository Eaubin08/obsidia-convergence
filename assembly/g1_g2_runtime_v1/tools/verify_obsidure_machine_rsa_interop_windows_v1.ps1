<#
.SYNOPSIS
    Preuve de compatibilite native Windows -> Python pour la cle Obsidure.
.DESCRIPTION
    Lecture de l'identite existante, signature d'un challenge aleatoire en
    memoire via Cert:\CurrentUser\My, verification Python avec le meme
    controle RSA public que le recu C278. Aucun certificat cree ou remplace,
    aucun fichier ecrit, aucune preuve de test C278 historique fabriquee.
    -ExpectedPublicSha256 est obligatoire et n'est pas une HumanApproval.
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPublicSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$machine = [Environment]::MachineName.ToUpperInvariant()
if ($machine -ne 'DESKTOP-Q5MD7J7') {
    throw "OBSIDURE_INTEROP_WRONG_MACHINE:$machine"
}
$subject = "CN=OBSIDIA-OBSIDURE-$machine"
$certs = @(Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -eq $subject })
if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey) {
    throw 'OBSIDURE_INTEROP_LOCAL_CERTIFICATE_UNAVAILABLE'
}
$cert = $certs[0]
$der = $cert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}
if ($digest -ne $ExpectedPublicSha256) {
    throw 'OBSIDURE_INTEROP_PUBLIC_CERTIFICATE_PIN_MISMATCH'
}

# L'enrolement public initial du portable doit correspondre au magasin local.
$proposalFile = Join-Path $env:USERPROFILE (
    "Downloads\OBSIDURE_PUBLIC_IDENTITY_$machine.json"
)
if (-not (Test-Path -LiteralPath $proposalFile -PathType Leaf)) {
    throw 'OBSIDURE_INTEROP_PUBLIC_ENROLLMENT_PROPOSAL_MISSING'
}
$proposal = Get-Content -LiteralPath $proposalFile -Raw | ConvertFrom-Json
if ($proposal.schema -ne 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1' -or
    $proposal.machine_id -ne $machine -or
    $proposal.public_certificate_sha256 -cne $ExpectedPublicSha256 -or
    $proposal.public_certificate_der_base64 -cne ([Convert]::ToBase64String($der))) {
    throw 'OBSIDURE_INTEROP_PROPOSAL_CERTIFICATE_BINDING_MISMATCH'
}

$private = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($null -eq $private) {
    throw 'OBSIDURE_INTEROP_PRIVATE_KEY_INACCESSIBLE'
}
try {
    if ($private.KeySize -lt 3072) {
        throw 'OBSIDURE_INTEROP_RSA_KEY_TOO_SMALL'
    }
    $nonce = [Guid]::NewGuid().ToString('N')
    $challenge = [System.Text.Encoding]::UTF8.GetBytes(
        "OBSIDIA_OBSIDURE_MACHINE_INTEROP_V1`0${machine}|$nonce"
    )
    $signature = $private.SignData(
        $challenge,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
}
finally {
    $private.Dispose()
}

$verifier = Join-Path $PSScriptRoot 'verify_obsidure_machine_challenge_v1.py'
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw 'OBSIDURE_INTEROP_PYTHON_VERIFIER_MISSING'
}

$envelope = [ordered]@{
    schema = 'OBSIDURE_WINDOWS_RSA_INTEROP_CHALLENGE_V1'
    expected_machine_id = $machine
    public_certificate_der_base64 = [Convert]::ToBase64String($der)
    pinned_certificate_sha256 = $digest
    challenge_base64 = [Convert]::ToBase64String($challenge)
    signature_base64 = [Convert]::ToBase64String($signature)
}
$json = $envelope | ConvertTo-Json -Compress -Depth 3
$out = $json | & py -3 -B -X utf8 $verifier
$rc = $LASTEXITCODE
$out | ForEach-Object { Write-Host $_ }
if ($rc -ne 0) {
    throw "OBSIDURE_INTEROP_PYTHON_VERIFICATION_HOLD_$rc"
}
Write-Host 'PRIVATE_KEY_EXPORTED=False'
Write-Host 'ENROLLMENT_APPROVED=False'
