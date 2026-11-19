<#
.SYNOPSIS
    Identité cryptographique Obsidure par PC, en deux modes explicites.
.DESCRIPTION
    Sans -Enroll : audit lecture seule du magasin utilisateur Windows.
    Avec -Enroll : crée volontairement UNE clé RSA 3072 non exportable dans
    Cert:\CurrentUser\My, puis exporte UNIQUEMENT son certificat PUBLIC dans
    Downloads. Ne touche ni au FIX ni aux worktrees, et ne signe aucun test.
    Le certificat auto-signé n'est pas une validation du poste ou de la personne.
#>
param([switch]$Enroll)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$machine = [Environment]::MachineName.ToUpperInvariant()
$allowed = @('DESKTOP-Q5MD7J7', 'DESKTOP-SDOG0EL')
if ($machine -notin $allowed) {
    throw "OBSIDURE_MACHINE_NOT_IN_PLANNED_REGISTRY:$machine"
}
if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw 'WINDOWS_PKI_CMDLET_NOT_AVAILABLE'
}

$subject = "CN=OBSIDIA-OBSIDURE-$machine"
$certificates = @(Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -eq $subject })

Write-Host "OBSIDURE_MACHINE=$machine"
Write-Host 'KEY_MODEL=PER_MACHINE_NON_EXPORTABLE_RSA3072'
Write-Host 'KEY_STORE=Cert:\CurrentUser\My'
Write-Host "EXISTING_IDENTITY_CERTIFICATES=$($certificates.Count)"

if (-not $Enroll) {
    Write-Host 'MODE=CHECK_ONLY'
    foreach ($cert in $certificates) {
        Write-Host "CERT_THUMBPRINT=$($cert.Thumbprint)"
        Write-Host "CERT_EXPIRES=$($cert.NotAfter.ToString('o'))"
    }
    Write-Host 'OBSIDURE_MACHINE_IDENTITY_CHECK_PASS=True'
    return
}

if ($certificates.Count -ne 0) {
    throw 'OBSIDURE_IDENTITY_EXISTS__NO_DUPLICATE_NO_REPLACEMENT'
}

$downloads = Join-Path $env:USERPROFILE 'Downloads'
if (-not (Test-Path -LiteralPath $downloads -PathType Container)) {
    throw 'DOWNLOADS_FOLDER_MISSING'
}
$output = Join-Path $downloads ("OBSIDURE_PUBLIC_IDENTITY_$machine.json")
if (Test-Path -LiteralPath $output) {
    throw 'PUBLIC_IDENTITY_PROPOSAL_ALREADY_EXISTS__NO_OVERWRITE'
}

$params = @{
    Type = 'Custom'
    Subject = $subject
    Provider = 'Microsoft Software Key Storage Provider'
    KeyAlgorithm = 'RSA'
    KeyLength = 3072
    HashAlgorithm = 'SHA256'
    KeyExportPolicy = 'NonExportable'
    KeyUsage = 'DigitalSignature'
    CertStoreLocation = 'Cert:\CurrentUser\My'
    NotAfter = (Get-Date).AddYears(1)
}

# EFFET EXPLICITE : seulement si l'utilisateur a donné -Enroll.
$certificate = New-SelfSignedCertificate @params
if (-not $certificate -or -not $certificate.HasPrivateKey) {
    throw 'OBSIDURE_CERTIFICATE_CREATION_NOT_CONFIRMED'
}

$publicDer = $certificate.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = [BitConverter]::ToString($sha.ComputeHash($publicDer)).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha.Dispose()
}

$proposal = [ordered]@{
    schema = 'OBSIDIA_OBSIDURE_PUBLIC_MACHINE_ENROLLMENT_PROPOSAL_V1'
    machine_id = $machine
    enrollment_state = 'ENROLLED_AWAITING_REVIEW'
    public_certificate_der_base64 = [Convert]::ToBase64String($publicDer)
    public_certificate_sha256 = $digest
    responsible_refs = @()
    proposed_roles = @('OBSIDURE_TEST_EVIDENCE_PRODUCER')
    enrollment_review_ref = $null
    private_key_exported = $false
    key_store = 'Cert:\CurrentUser\My'
    decision_authority = 'KX108_ONLY'
    human_approval_verified = $false
    execution_authorized = $false
}

$proposal | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $output -Encoding UTF8 -ErrorAction Stop

Write-Host 'MODE=EXPLICIT_ENROLL'
Write-Host "PUBLIC_PROPOSAL=$output"
Write-Host "PUBLIC_CERT_SHA256=$digest"
Write-Host 'PRIVATE_KEY_EXPORTED=False'
Write-Host 'ENROLLMENT_APPROVED=False'
Write-Host 'KX108_AUTHORITY=UNCHANGED'
Write-Host 'RELEASE=HOLD'
