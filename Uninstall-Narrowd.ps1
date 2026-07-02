#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the narrowd Windows service.

.DESCRIPTION
    Stops and removes the narrowd Windows service and, by default, removes the
    inbound Windows Firewall rule created by Install-Narrowd.ps1.

    Optionally removes the installed narrowd.exe copy from the stable install
    directory.

    Optionally removes the generated narrowd data directory under the target
    user's AppData\Local profile.

.PARAMETER ServiceName
    Windows service name. Default: narrowd.

.PARAMETER Port
    TCP port used for the firewall rule name. Default: 2222.

.PARAMETER KeepFirewall
    Leave the inbound firewall rule in place.

.PARAMETER RemoveBinary
    Remove the installed narrowd.exe copy from the stable install directory.

.PARAMETER BinaryInstallDir
    Directory that contains the installed narrowd.exe copy when -RemoveBinary
    is used. Default: AppData\Local\narrowd\bin for the target user.

.PARAMETER RemoveData
    Remove %APPDATA%\narrowd for the specified user profile.

.PARAMETER UserName
    Windows account whose %APPDATA%\narrowd directory should be removed when
    -RemoveData is used.

.EXAMPLE
    .\Uninstall-Narrowd.ps1

.EXAMPLE
    .\Uninstall-Narrowd.ps1 -ServiceName narrowd -Port 2222

.EXAMPLE
    .\Uninstall-Narrowd.ps1 -RemoveBinary

.EXAMPLE
    .\Uninstall-Narrowd.ps1 -RemoveData -UserName alice
#>

param(
    [string]$ServiceName = 'narrowd',

    [ValidateRange(1, 65535)]
    [int]$Port = 2222,

    [switch]$KeepFirewall,

    [switch]$RemoveBinary,

    [string]$BinaryInstallDir,

    [switch]$RemoveData,

    [string]$UserName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function OK([string]$Message)   { Write-Host "    ok  $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "    WARN $Message" -ForegroundColor Yellow }

function Get-DefaultCurrentUserNarrowdRoot() {
    $localAppData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        $localAppData = $env:LOCALAPPDATA
    }
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw "Unable to determine the Local AppData directory."
    }

    return (Join-Path $localAppData 'narrowd')
}

function Get-DefaultNarrowdRoot([string]$ProfileDir) {
    if ([string]::IsNullOrWhiteSpace($ProfileDir)) {
        throw "Profile directory cannot be empty."
    }

    return (Join-Path $ProfileDir 'AppData\Local\narrowd')
}

function Get-DefaultBinaryInstallDir([string]$NarrowdRoot) {
    return (Join-Path $NarrowdRoot 'bin')
}

function Remove-ServiceIfPresent([string]$Name) {
    $existing = Get-Service $Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        Warn "Service '$Name' not found - skipping"
        return
    }

    if ($existing.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $Name -Force -ErrorAction Stop
            $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            OK "Stopped service '$Name'"
        } catch {
            Warn "Failed to stop service cleanly: $($_.Exception.Message)"
        }
    }

    & sc.exe delete $Name | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        if (-not (Get-Service $Name -ErrorAction SilentlyContinue)) {
            OK "Removed service '$Name'"
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "Service '$Name' is still present after deletion."
}

function Resolve-ProfilePath([string]$Name) {
    $bare = $Name -replace '^.*\\', ''

    $profile = Get-WmiObject Win32_UserProfile `
        -Filter "LocalPath LIKE '%\\$bare'" -ErrorAction SilentlyContinue |
        Sort-Object -Property LastUseTime -Descending |
        Select-Object -First 1 -ExpandProperty LocalPath
    if ($profile) { return $profile }

    $fallback = "C:\Users\$bare"
    if (Test-Path $fallback) { return $fallback }

    throw (
        "Cannot locate Windows profile for '$Name'. " +
        "Ensure the account exists and has logged in at least once, " +
        "or create C:\Users\$bare manually."
    )
}

$narrowdRoot = $null
if (-not [string]::IsNullOrWhiteSpace($UserName)) {
    $narrowdRoot = Get-DefaultNarrowdRoot (Resolve-ProfilePath $UserName)
} else {
    $narrowdRoot = Get-DefaultCurrentUserNarrowdRoot
}

if ([string]::IsNullOrWhiteSpace($BinaryInstallDir)) {
    $BinaryInstallDir = Get-DefaultBinaryInstallDir $narrowdRoot
}

Step "Removing service '$ServiceName'"
Remove-ServiceIfPresent $ServiceName

if (-not $KeepFirewall) {
    Step "Removing inbound firewall rule (TCP $Port)"
    $ruleName = "narrowd SSH (port $Port)"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $ruleName | Out-Null
        OK "Removed rule '$ruleName'"
    } else {
        Warn "Firewall rule '$ruleName' not found - skipping"
    }
}

if ($RemoveBinary) {
    Step "Removing installed binary"
    $binaryPath = Join-Path $BinaryInstallDir 'narrowd.exe'
    if (Test-Path $binaryPath) {
        Remove-Item $binaryPath -Force
        OK "Removed $binaryPath"
    } else {
        Warn "Installed binary '$binaryPath' not found - skipping"
    }

    if ((Test-Path $BinaryInstallDir) -and -not (Get-ChildItem $BinaryInstallDir -Force | Select-Object -First 1)) {
        Remove-Item $BinaryInstallDir -Force
        OK "Removed empty directory $BinaryInstallDir"
    }
}

if ($RemoveData) {
    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw "Pass -UserName when using -RemoveData."
    }

    Step "Removing narrowd data for '$UserName'"
    if (Test-Path $narrowdRoot) {
        Remove-Item $narrowdRoot -Recurse -Force
        OK "Removed $narrowdRoot"
    } else {
        Warn "Data directory '$narrowdRoot' not found - skipping"
    }
}

$bar = '=' * 56
Write-Host ""
Write-Host $bar -ForegroundColor Green
Write-Host " narrowd uninstalled" -ForegroundColor Green
Write-Host $bar -ForegroundColor Green
Write-Host ""
Write-Host ("  Service name : " + $ServiceName)
Write-Host ("  Firewall     : " + $(if ($KeepFirewall) { 'kept' } else { "removed for port $Port" }))
if ($RemoveBinary) {
    Write-Host ("  Binary       : removed from " + $BinaryInstallDir)
} else {
    Write-Host ("  Binary       : kept")
}
if ($RemoveData) {
    Write-Host ("  Data removed : yes")
} else {
    Write-Host ("  Data removed : no")
}
Write-Host ""
