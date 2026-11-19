<#
G4O — identité administrative du fondateur, distincte de la clé PC Obsidure.
Sans -Enroll : inspection uniquement. Avec -Enroll : création persistante d'un
certificat RSA3072 non exportable, puis export du SEUL certificat PUBLIC.
Cette action ne vaut pas une approbation indépendante de l'identité humaine.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$WorktreePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedSourceHead,

    [switch]$Enroll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$machine = [Environment]::MachineName.ToUpperInvariant()
if ($machine -cne 'DESKTOP-Q5MD7J7') { throw 'G4O_WRONG_PC' }
if (-not (Test-Path -LiteralPath (Join-Path $WorktreePath '.git'))) {
    throw 'G4O_WORKTREE_NOT_FOUND'
}
$actualHead = (& git -C $WorktreePath rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualHead -cne $ExpectedSourceHead) {
    throw 'G4O_SOURCE_HEAD_MISMATCH'
}
$changes = @(& git -C $WorktreePath status --porcelain)
if ($LASTEXITCODE -ne 0 -or $changes.Count -gt 0) {
    throw 'G4O_WORKTREE_NOT_CLEAN'
}

function Get-RsaPublicMaterial {
    param($Certificate)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if ($null -eq $rsa) { throw 'G4O_RSA_PUBLIC_KEY_UNAVAILABLE' }
    try {
        if ($rsa.KeySize -lt 3072) { throw 'G4O_RSA_KEY_TOO_SMALL' }
        $parameters = $rsa.ExportParameters($false)
        if ($null -eq $parameters.Modulus -or $null -eq $parameters.Exponent) {
            throw 'G4O_RSA_PARAMETERS_UNAVAILABLE'
        }
        return ([Convert]::ToBase64String($parameters.Modulus) + '|' +
            [Convert]::ToBase64String($parameters.Exponent))
    }
    finally { $rsa.Dispose() }
}

function Get-CertificateSha256 {
    param($Certificate)
    $raw = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($digest.ComputeHash($raw)).Replace('-', '').ToLowerInvariant()
    }
    finally { $digest.Dispose() }
}

$machineSubject = 'CN=OBSIDIA-OBSIDURE-DESKTOP-Q5MD7J7'
$founderSubject = 'CN=OBSIDIA-ADMIN-FOUNDER-ETIENNE'
$expectedMachinePin = '5bb3f8688930de497254185292a49b46c2f88b0bb23cf259711e86981932c398'

$pcCerts = @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -ceq $machineSubject })
if ($pcCerts.Count -ne 1 -or -not $pcCerts[0].HasPrivateKey) {
    throw 'G4O_PORTABLE_MACHINE_IDENTITY_MISSING_OR_AMBIGUOUS'
}
$pcPin = Get-CertificateSha256 -Certificate $pcCerts[0]
if ($pcPin -cne $expectedMachinePin) { throw 'G4O_PORTABLE_MACHINE_PIN_MISMATCH' }
$pcKey = Get-RsaPublicMaterial -Certificate $pcCerts[0]

$founders = @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -ceq $founderSubject })
if ($founders.Count -gt 1) { throw 'G4O_FOUNDER_IDENTITY_AMBIGUOUS' }
if ($founders.Count -eq 1) {
    if (-not $founders[0].HasPrivateKey) { throw 'G4O_FOUNDER_PRIVATE_KEY_MISSING' }
    if ($founders[0].NotAfter -le (Get-Date) -or $founders[0].NotBefore -gt (Get-Date)) {
        throw 'G4O_FOUNDER_CERTIFICATE_OUTSIDE_VALIDITY'
    }
    $founderKey = Get-RsaPublicMaterial -Certificate $founders[0]
    if ($founderKey -ceq $pcKey) { throw 'G4O_FOUNDER_PC_RSA_KEY_REUSE_DENIED' }
}

$downloads = Join-Path $env:USERPROFILE 'Downloads'
if (-not (Test-Path -LiteralPath $downloads -PathType Container)) {
    throw 'G4O_DOWNLOADS_NOT_AVAILABLE'
}
$proposalPath = Join-Path $downloads 'OBSIDURE_FOUNDER_PUBLIC_IDENTITY_DESKTOP-Q5MD7J7.json'
if ((Test-Path -LiteralPath $proposalPath -PathType Leaf) -and $founders.Count -eq 1) {
    $existing = Get-Content -LiteralPath $proposalPath -Raw | ConvertFrom-Json
    $founderPin = Get-CertificateSha256 -Certificate $founders[0]
    $founderDer = $founders[0].Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    if ($existing.schema -cne 'OBSIDIA_G4O_FOUNDER_PUBLIC_ADMIN_ENROLLMENT_PROPOSAL_V1' -or
        $existing.founder_admin_id -cne 'FOUNDER-ETIENNE' -or
        $existing.public_certificate_sha256 -cne $founderPin -or
        $existing.public_certificate_der_base64 -cne [Convert]::ToBase64String($founderDer) -or
        $existing.machine_certificate_sha256 -cne $pcPin) {
        throw 'G4O_EXISTING_PUBLIC_PROPOSAL_MISMATCH'
    }
}

Write-Host 'G4O_FOUNDER_ID=FOUNDER-ETIENNE'
Write-Host "MACHINE=$machine"
Write-Host 'KEY_STORE=Cert:\CurrentUser\My'
Write-Host 'ADMIN_SCOPE=OBSIDURE_MACHINE_ENROLLMENT_REVIEW_ONLY'
Write-Host "FOUNDER_CERTIFICATES_FOUND=$($founders.Count)"

if (-not $Enroll) {
    Write-Host 'MODE=CHECK_ONLY'
    Write-Host "FOUNDER_KEY_PRESENT=$($founders.Count -eq 1)"
    Write-Host "PUBLIC_PROPOSAL_PRESENT=$(Test-Path -LiteralPath $proposalPath -PathType Leaf)"
    Write-Host 'FOUNDER_INDEPENDENTLY_APPROVED=False'
    Write-Host 'TEAM_MODE_ACTIVATED=False'
    Write-Host 'KX108_AUTHORITY=UNCHANGED'
    Write-Host 'RELEASE=HOLD'
    return
}

if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw 'G4O_WINDOWS_CERTIFICATE_CMDLET_MISSING'
}
if (Test-Path -LiteralPath $proposalPath) {
    throw 'G4O_PUBLIC_PROPOSAL_EXISTS_NO_OVERWRITE'
}

if ($founders.Count -eq 0) {
    $params = @{
        Type = 'Custom'
        Subject = $founderSubject
        Provider = 'Microsoft Software Key Storage Provider'
        KeyAlgorithm = 'RSA'
        KeyLength = 3072
        HashAlgorithm = 'SHA256'
        KeyExportPolicy = 'NonExportable'
        KeyUsage = 'DigitalSignature'
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter = (Get-Date).AddYears(1)
    }
    # SEUL effet persistent — nécessite -Enroll explicitement.
    $newCert = New-SelfSignedCertificate @params
    if ($null -eq $newCert -or -not $newCert.HasPrivateKey) {
        throw 'G4O_FOUNDER_CERTIFICATE_CREATION_FAILED'
    }
    $founders = @($newCert)
}

$founder = $founders[0]
$founderKey = Get-RsaPublicMaterial -Certificate $founder
if ($founderKey -ceq $pcKey) { throw 'G4O_FOUNDER_PC_RSA_KEY_REUSE_DENIED' }
if ($founder.NotAfter -le (Get-Date)) { throw 'G4O_FOUNDER_CERTIFICATE_EXPIRED' }

$der = $founder.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$pin = Get-CertificateSha256 -Certificate $founder
$record = [ordered]@{
    schema = 'OBSIDIA_G4O_FOUNDER_PUBLIC_ADMIN_ENROLLMENT_PROPOSAL_V1'
    founder_admin_id = 'FOUNDER-ETIENNE'
    enrollment_state = 'KEY_PROPOSED_AWAITING_INDEPENDENT_REVIEW'
    admin_scope = 'OBSIDURE_MACHINE_ENROLLMENT_REVIEW_ONLY'
    source_machine_id = $machine
    public_certificate_der_base64 = [Convert]::ToBase64String($der)
    public_certificate_sha256 = $pin
    machine_certificate_sha256 = $pcPin
    private_key_exported = $false
    founder_independently_approved = $false
    team_mode_activated = $false
    decision_authority = 'KX108_ONLY'
    release_authorized = $false
}
$record | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $proposalPath -Encoding UTF8 -ErrorAction Stop

Write-Host 'MODE=EXPLICIT_ENROLL'
Write-Host "PUBLIC_PROPOSAL=$proposalPath"
Write-Host "FOUNDER_PUBLIC_CERT_SHA256=$pin"
Write-Host 'FOUNDER_KEY_DIFFERS_FROM_PC_RSA=True'
Write-Host 'PRIVATE_KEY_EXPORTED=False'
Write-Host 'FOUNDER_INDEPENDENTLY_APPROVED=False'
Write-Host 'TEAM_MODE_ACTIVATED=False'
Write-Host 'KX108_AUTHORITY=UNCHANGED'
Write-Host 'RELEASE=HOLD'
