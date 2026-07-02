<#
.SYNOPSIS
    Installs a previously built narrowd MSIX package for the current user.

.DESCRIPTION
    Imports the companion signing certificate into the current user's
    TrustedPeople store and registers the MSIX package with Add-AppxPackage.

    The package starts narrowd in the user's own session after the next sign-in.
    It writes runtime state to %LOCALAPPDATA%\narrowd.

.PARAMETER MsixPath
    Path to the .msix package. Defaults to the newest file under target\msix.

.PARAMETER CertificatePath
    Path to the exported .cer file. Defaults to the matching .cer beside the
    package, or the newest .cer under target\msix.

.PARAMETER ForceReinstall
    Remove any currently installed package with the same identity name before
    adding the new one. Useful when reinstalling the same version.

.EXAMPLE
    .\Install-NarrowdMsix.ps1

.EXAMPLE
    .\Install-NarrowdMsix.ps1 -MsixPath .\target\msix\Cre4ture.Narrowd_0.3.2.0_x64.msix -ForceReinstall
#>

param(
    [string]$MsixPath,

    [string]$CertificatePath,

    [switch]$ForceReinstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function OK([string]$Message)   { Write-Host "    ok  $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "    WARN $Message" -ForegroundColor Yellow }

function Resolve-LatestFile([string]$DirectoryPath, [string]$Filter) {
    $item = Get-ChildItem -LiteralPath $DirectoryPath -Filter $Filter -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $item) {
        throw "Unable to find $Filter under $DirectoryPath"
    }

    return $item.FullName
}

function Read-PackageIdentity([string]$PackagePath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        $entry = $archive.GetEntry('AppxManifest.xml')
        if (-not $entry) {
            throw "AppxManifest.xml not found inside $PackagePath"
        }

        $stream = $entry.Open()
        $reader = New-Object System.IO.StreamReader($stream)
        try {
            $xml = [xml]$reader.ReadToEnd()
        } finally {
            $reader.Dispose()
            $stream.Dispose()
        }

        return [pscustomobject]@{
            Name = $xml.Package.Identity.Name
            Publisher = $xml.Package.Identity.Publisher
            Version = $xml.Package.Identity.Version
        }
    } finally {
        $archive.Dispose()
    }
}

if ([string]::IsNullOrWhiteSpace($MsixPath)) {
    $MsixPath = Resolve-LatestFile -DirectoryPath (Join-Path $PSScriptRoot 'target\msix') -Filter '*.msix'
}

$MsixPath = (Resolve-Path -LiteralPath $MsixPath).Path

if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
    $baseCertificate = [System.IO.Path]::ChangeExtension($MsixPath, '.cer')
    if (Test-Path -LiteralPath $baseCertificate) {
        $CertificatePath = $baseCertificate
    } else {
        $CertificatePath = Resolve-LatestFile -DirectoryPath (Split-Path $MsixPath -Parent) -Filter '*.cer'
    }
}

$CertificatePath = (Resolve-Path -LiteralPath $CertificatePath).Path
$identity = Read-PackageIdentity -PackagePath $MsixPath
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)

Step "Importing signing certificate"
$existingCert = Get-ChildItem Cert:\CurrentUser\TrustedPeople |
    Where-Object { $_.Thumbprint -eq $certificate.Thumbprint } |
    Select-Object -First 1
if (-not $existingCert) {
    Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
    OK $CertificatePath
} else {
    OK "Certificate already trusted"
}

if ($ForceReinstall) {
    Step "Removing existing package registrations"
    $existingPackages = Get-AppxPackage -Name $identity.Name -ErrorAction SilentlyContinue
    if ($existingPackages) {
        foreach ($package in $existingPackages) {
            Remove-AppxPackage -Package $package.PackageFullName
            OK "Removed $($package.PackageFullName)"
        }
    } else {
        Warn "No installed package named '$($identity.Name)' found"
    }
}

Step "Installing MSIX package"
Add-AppxPackage -Path $MsixPath -ForceApplicationShutdown
OK $MsixPath

$bar = '=' * 54
Write-Host ""
Write-Host $bar -ForegroundColor Green
Write-Host " narrowd MSIX installed" -ForegroundColor Green
Write-Host $bar -ForegroundColor Green
Write-Host ""
Write-Host ("  Package name : " + $identity.Name)
Write-Host ("  Version      : " + $identity.Version)
Write-Host ("  Publisher    : " + $identity.Publisher)
Write-Host ("  Certificate  : " + $CertificatePath)
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Sign out and sign back in once to trigger the startup task."
Write-Host "  2. Add your public key to:"
Write-Host ("       " + (Join-Path $HOME '.ssh\authorized_keys'))
Write-Host "  3. Edit the generated config if needed:"
Write-Host ("       " + (Join-Path $env:LOCALAPPDATA 'narrowd\narrowd.conf'))
Write-Host "  4. Review logs:"
Write-Host ("       " + (Join-Path $env:LOCALAPPDATA 'narrowd\log\narrowd.log'))
Write-Host ""
