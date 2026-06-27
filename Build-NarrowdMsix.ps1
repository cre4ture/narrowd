<#
.SYNOPSIS
    Builds a signed MSIX package that starts narrowd in the signed-in user session.

.DESCRIPTION
    This script packages the Windows session launcher and the narrowd CLI into an
    MSIX package. The resulting package:

      - Registers a startup task for the current user
      - Starts narrowd automatically after the user signs in
      - Opens the default inbound TCP 2223 firewall hole declaratively
      - Keeps config, host key, and logs under %LOCALAPPDATA%\narrowd

    Output files are written to target\msix by default:

      - *.msix  signed package
      - *.cer   public signing certificate for installation on another machine

    The package is intended for sideloading or trusted internal distribution.
    For Microsoft Store submission, replace the development certificate and
    review the restricted startup-task capability.

.PARAMETER PackageName
    Package identity name. Default: Cre4ture.Narrowd

.PARAMETER Publisher
    Publisher subject used in the package identity and signing certificate.
    Default: CN=narrowd-dev

.PARAMETER DisplayName
    User-facing application name. Default: narrowd

.PARAMETER PublisherDisplayName
    User-facing publisher name. Default: narrowd

.PARAMETER Description
    Package description shown in Windows. Default describes the session service.

.PARAMETER Architecture
    Target package architecture. Default: x64

.PARAMETER PackageVersion
    Four-part MSIX package version. Defaults to the Cargo version plus ".0".

.PARAMETER OutputDir
    Target directory for staging, certificate, and MSIX output.

.PARAMETER CargoTargetDir
    Dedicated cargo target directory used for the MSIX build artifacts.
    Default: target\msix-build

.PARAMETER SkipBuild
    Skip the cargo build step and package existing release binaries.

.PARAMETER Force
    Overwrite the output directory contents.

.EXAMPLE
    .\Build-NarrowdMsix.ps1

.EXAMPLE
    .\Build-NarrowdMsix.ps1 -PackageVersion 0.3.2.5 -Publisher "CN=My Lab"
#>

param(
    [string]$PackageName = 'Cre4ture.Narrowd',

    [string]$Publisher = 'CN=narrowd-dev',

    [string]$DisplayName = 'narrowd',

    [string]$PublisherDisplayName = 'narrowd',

    [string]$Description = 'Single-user SSH daemon that auto-starts in the signed-in user session.',

    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Architecture = 'x64',

    [string]$PackageVersion,

    [string]$OutputDir = (Join-Path $PSScriptRoot 'target\msix'),

    [string]$CargoTargetDir = (Join-Path $PSScriptRoot 'target\msix-build'),

    [switch]$SkipBuild,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function OK([string]$Message)   { Write-Host "    ok  $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "    WARN $Message" -ForegroundColor Yellow }

function Get-CargoVersion([string]$CargoTomlPath) {
    $match = Select-String -Path $CargoTomlPath -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Unable to determine package version from $CargoTomlPath"
    }

    return $match.Matches[0].Groups[1].Value
}

function Convert-ToMsixVersion([string]$VersionText) {
    $core = $VersionText.Split('-', 2)[0]
    $parts = $core.Split('.')
    if ($parts.Count -lt 1 -or $parts.Count -gt 4) {
        throw "Unsupported version format '$VersionText'"
    }

    while ($parts.Count -lt 4) {
        $parts += '0'
    }

    foreach ($part in $parts) {
        $parsed = 0
        if (-not [int]::TryParse($part, [ref]$parsed) -or $parsed -lt 0 -or $parsed -gt 65535) {
            throw "Invalid MSIX version component '$part' in '$VersionText'"
        }
    }

    return ($parts[0..3] -join '.')
}

function Resolve-WindowsKitTool([string]$ToolName, [string]$ToolArch) {
    $candidates = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' `
        -Filter $ToolName -Recurse -ErrorAction SilentlyContinue |
        Where-Object { (Split-Path $_.DirectoryName -Leaf) -eq $ToolArch } |
        Sort-Object FullName -Descending

    $tool = $candidates | Select-Object -First 1
    if (-not $tool) {
        throw "Unable to locate $ToolName for $ToolArch under the Windows 10 SDK."
    }

    return $tool.FullName
}

function Assert-WithinRepo([string]$CandidatePath, [string]$RepoRoot) {
    $fullCandidate = [System.IO.Path]::GetFullPath($CandidatePath)
    $fullRepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
    if (-not $fullCandidate.StartsWith($fullRepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify '$fullCandidate' because it is outside '$fullRepoRoot'."
    }
}

function Reset-Directory([string]$PathToReset, [string]$RepoRoot) {
    Assert-WithinRepo -CandidatePath $PathToReset -RepoRoot $RepoRoot

    if (Test-Path -LiteralPath $PathToReset) {
        Remove-Item -LiteralPath $PathToReset -Recurse -Force
    }

    New-Item -ItemType Directory -Path $PathToReset -Force | Out-Null
}

function Ensure-CodeSigningCertificate(
    [string]$Subject,
    [string]$FriendlyName,
    [string]$CertificatePath
) {
    $certificate = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -eq $Subject -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date).AddDays(30)
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $certificate) {
        Step "Creating development code-signing certificate"
        $certificate = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $Subject `
            -FriendlyName $FriendlyName `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(3)
        OK "Created certificate $($certificate.Thumbprint)"
    } else {
        OK "Using existing certificate $($certificate.Thumbprint)"
    }

    Export-Certificate -Cert $certificate -FilePath $CertificatePath -Force | Out-Null
    return $certificate
}

function New-LogoAsset([string]$Path, [int]$Size) {
    Add-Type -AssemblyName System.Drawing

    $bitmap = New-Object System.Drawing.Bitmap($Size, $Size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.ColorTranslator]::FromHtml('#102033'))

    $ringMargin = [Math]::Max(2, [Math]::Round($Size * 0.08))
    $ringBrush = New-Object System.Drawing.SolidBrush(
        [System.Drawing.ColorTranslator]::FromHtml('#1f5f8b')
    )
    $textBrush = New-Object System.Drawing.SolidBrush(
        [System.Drawing.ColorTranslator]::FromHtml('#f5fbff')
    )
    $fontSize = [Math]::Round($Size * 0.38)
    $font = New-Object System.Drawing.Font(
        'Segoe UI Semibold',
        [float]$fontSize,
        [System.Drawing.FontStyle]::Bold,
        [System.Drawing.GraphicsUnit]::Pixel
    )
    $stringFormat = New-Object System.Drawing.StringFormat
    $stringFormat.Alignment = [System.Drawing.StringAlignment]::Center
    $stringFormat.LineAlignment = [System.Drawing.StringAlignment]::Center

    $diameter = $Size - (2 * $ringMargin)
    $graphics.FillEllipse($ringBrush, $ringMargin, $ringMargin, $diameter, $diameter)
    $graphics.DrawString(
        'nd',
        $font,
        $textBrush,
        [System.Drawing.RectangleF]::new(0, 0, $Size, $Size),
        $stringFormat
    )

    $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)

    $stringFormat.Dispose()
    $font.Dispose()
    $textBrush.Dispose()
    $ringBrush.Dispose()
    $graphics.Dispose()
    $bitmap.Dispose()
}

function Write-ManifestFromTemplate([string]$TemplatePath, [string]$DestinationPath, [hashtable]$Replacements) {
    $content = Get-Content -LiteralPath $TemplatePath -Raw
    foreach ($key in $Replacements.Keys) {
        $content = $content.Replace($key, $Replacements[$key])
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($DestinationPath, $content, $utf8NoBom)
}

$repoRoot = $PSScriptRoot
$cargoToml = Join-Path $repoRoot 'Cargo.toml'
$templatePath = Join-Path $repoRoot 'packaging\msix\AppxManifest.xml.in'
if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "MSIX manifest template not found: $templatePath"
}

if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
    $PackageVersion = Convert-ToMsixVersion (Get-CargoVersion $cargoToml)
}

$outputDirFull = [System.IO.Path]::GetFullPath($OutputDir)
$cargoTargetDirFull = [System.IO.Path]::GetFullPath($CargoTargetDir)
$stageDir = Join-Path $outputDirFull 'stage'
$assetsDir = Join-Path $stageDir 'Assets'
$packageBaseName = "{0}_{1}_{2}" -f $PackageName, $PackageVersion, $Architecture
$msixPath = Join-Path $outputDirFull ($packageBaseName + '.msix')
$certificatePath = Join-Path $outputDirFull ($packageBaseName + '.cer')
$manifestPath = Join-Path $stageDir 'AppxManifest.xml'

if ((Test-Path -LiteralPath $outputDirFull) -and -not $Force) {
    Warn "Output directory already exists: $outputDirFull"
    Warn "Pass -Force to replace its contents."
    throw "Refusing to overwrite existing MSIX output."
}

Step "Preparing output directories"
Reset-Directory -PathToReset $outputDirFull -RepoRoot $repoRoot
New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
OK $outputDirFull

$makeAppx = Resolve-WindowsKitTool -ToolName 'makeappx.exe' -ToolArch $Architecture
$signTool = Resolve-WindowsKitTool -ToolName 'signtool.exe' -ToolArch $Architecture
OK "makeappx: $makeAppx"
OK "signtool: $signTool"
OK "cargo target dir: $cargoTargetDirFull"

if (-not $SkipBuild) {
    Step "Building release binaries"
    Assert-WithinRepo -CandidatePath $cargoTargetDirFull -RepoRoot $repoRoot
    New-Item -ItemType Directory -Path $cargoTargetDirFull -Force | Out-Null
    Push-Location $repoRoot
    try {
        & cargo build --release --target-dir $cargoTargetDirFull --bin narrowd --bin narrowd-session-launcher
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed"
        }
    } finally {
        Pop-Location
    }
}

$releaseDir = Join-Path $cargoTargetDirFull 'release'
$requiredFiles = @(
    (Join-Path $releaseDir 'narrowd.exe'),
    (Join-Path $releaseDir 'narrowd-session-launcher.exe')
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $file)) {
        throw "Required binary missing: $file"
    }
}

Step "Staging package contents"
Copy-Item -LiteralPath (Join-Path $releaseDir 'narrowd.exe') -Destination (Join-Path $stageDir 'narrowd.exe')
Copy-Item -LiteralPath (Join-Path $releaseDir 'narrowd-session-launcher.exe') -Destination (Join-Path $stageDir 'narrowd-session-launcher.exe')
New-LogoAsset -Path (Join-Path $assetsDir 'StoreLogo.png') -Size 50
New-LogoAsset -Path (Join-Path $assetsDir 'Square44x44Logo.png') -Size 44
New-LogoAsset -Path (Join-Path $assetsDir 'Square150x150Logo.png') -Size 150
OK "Binaries and assets staged"

Step "Writing package manifest"
Write-ManifestFromTemplate `
    -TemplatePath $templatePath `
    -DestinationPath $manifestPath `
    -Replacements @{
        '__PACKAGE_NAME__' = $PackageName
        '__PUBLISHER__' = $Publisher
        '__PACKAGE_VERSION__' = $PackageVersion
        '__DISPLAY_NAME__' = $DisplayName
        '__PUBLISHER_DISPLAY_NAME__' = $PublisherDisplayName
        '__DESCRIPTION__' = $Description
        '__ARCH__' = $Architecture
    }
OK $manifestPath

Step "Preparing signing certificate"
$certificate = Ensure-CodeSigningCertificate `
    -Subject $Publisher `
    -FriendlyName "$DisplayName MSIX signing" `
    -CertificatePath $certificatePath
OK $certificatePath

Step "Packing MSIX"
& $makeAppx pack /o /d $stageDir /p $msixPath
if ($LASTEXITCODE -ne 0) {
    throw "makeappx failed"
}
OK $msixPath

Step "Signing MSIX"
& $signTool sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $msixPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool failed"
}
OK "Signed $msixPath"

$bar = '=' * 56
Write-Host ""
Write-Host $bar -ForegroundColor Green
Write-Host " narrowd MSIX package built" -ForegroundColor Green
Write-Host $bar -ForegroundColor Green
Write-Host ""
Write-Host ("  Package      : " + $msixPath)
Write-Host ("  Certificate  : " + $certificatePath)
Write-Host ("  Version      : " + $PackageVersion)
Write-Host ("  Publisher    : " + $Publisher)
Write-Host ""
Write-Host "Install for the current user:" -ForegroundColor Yellow
Write-Host ("  powershell -ExecutionPolicy Bypass -File `"" + (Join-Path $repoRoot 'Install-NarrowdMsix.ps1') + "`" -MsixPath `"" + $msixPath + "`"")
Write-Host ""
