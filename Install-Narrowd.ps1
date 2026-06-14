#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs narrowd as a Windows service running as the specified user account.

.DESCRIPTION
    narrowd is a single-user SSH daemon. It runs as the target user, so every
    SSH session gets exactly that user's file-system and process rights without
    any impersonation layer.

    This script:
      - Optionally copies narrowd.exe to a stable install directory
      - Resolves the user's Windows profile directory
      - Generates an ed25519 SSH host key
      - Writes a narrowd config with absolute paths
      - Locks the host key to the service account and Administrators
      - Grants "Log on as a service" to the account via the LSA policy API
      - Installs narrowd as a native Windows service
      - Adds an inbound Windows Firewall rule for the chosen port

    Install OpenSSH Client first if ssh-keygen is missing:
      Settings > System > Optional Features > OpenSSH Client

.PARAMETER UserName
    Windows account that owns all SSH sessions (for example "alice" or
    "DOMAIN\alice"). The daemon runs as this account.
    When prompted interactively, the default is the current Windows identity.

.PARAMETER BinaryPath
    Full path to narrowd.exe.
    When prompted interactively, the default is the first existing path from:
      - target\release\narrowd.exe under the script directory
      - target\debug\narrowd.exe under the script directory
      - narrowd.exe under the script directory
      - narrowd.exe from PATH

.PARAMETER Port
    TCP port narrowd listens on. Default: 2222.

.PARAMETER ServiceName
    Windows service name. Default: narrowd.

.PARAMETER BinaryInstallDir
    Directory where a stable copy of narrowd.exe should be placed when the
    binary copy step is enabled. Default: AppData\Local\narrowd\bin under the
    target user's profile.

.PARAMETER Force
    Remove and reinstall an existing service, overwrite an existing config.
    When prompted interactively, the default is No.

.PARAMETER NoFirewall
    Skip creating the inbound firewall rule.
    When prompted interactively, the default is No.

.PARAMETER NoBinaryCopy
    Skip copying narrowd.exe to the stable install directory and use the
    provided BinaryPath directly. When prompted interactively, the default is
    No.

.EXAMPLE
    .\Install-Narrowd.ps1

.EXAMPLE
    .\Install-Narrowd.ps1 -UserName alice -BinaryPath "C:\Tools\narrowd\narrowd.exe"

.EXAMPLE
    .\Install-Narrowd.ps1 -UserName alice -BinaryPath "C:\Tools\narrowd\narrowd.exe" -Port 22 -Force
#>

param(
    [string]$UserName,

    [string]$BinaryPath,

    [ValidateRange(1, 65535)]
    [int]$Port = 2222,

    [string]$ServiceName = 'narrowd',

    [string]$BinaryInstallDir,

    [switch]$Force,

    [switch]$NoFirewall,

    [switch]$NoBinaryCopy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function OK([string]$Message)   { Write-Host "    ok  $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "    WARN $Message" -ForegroundColor Yellow }

function Get-DefaultUserName() {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-not [string]::IsNullOrWhiteSpace($identity)) {
        return $identity
    }

    if ($env:USERDOMAIN -and $env:USERNAME) {
        return "$($env:USERDOMAIN)\$($env:USERNAME)"
    }

    if ($env:USERNAME) {
        return $env:USERNAME
    }

    throw "Unable to determine a default Windows account. Pass -UserName explicitly."
}

function Get-DefaultBinaryPath() {
    $candidates = @(
        (Join-Path $PSScriptRoot 'target\release\narrowd.exe'),
        (Join-Path $PSScriptRoot 'target\debug\narrowd.exe'),
        (Join-Path $PSScriptRoot 'narrowd.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $command = Get-Command narrowd.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Path
    }

    return $candidates[0]
}

function Get-DefaultNarrowdRoot([string]$ProfileDir) {
    if ([string]::IsNullOrWhiteSpace($ProfileDir)) {
        throw "Profile directory cannot be empty."
    }

    return (Join-Path $ProfileDir 'AppData\Local\narrowd')
}

function Get-DefaultBinaryInstallDir([string]$ProfileDir) {
    return (Join-Path (Get-DefaultNarrowdRoot $ProfileDir) 'bin')
}

function Prompt-WithDefault([string]$Prompt, [string]$Default) {
    $response = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }

    return $response.Trim()
}

function Prompt-IntWithDefault(
    [string]$Prompt,
    [int]$Default,
    [int]$Minimum,
    [int]$Maximum
) {
    while ($true) {
        $response = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $Default
        }

        $value = 0
        if ([int]::TryParse($response.Trim(), [ref]$value) -and
            $value -ge $Minimum -and
            $value -le $Maximum) {
            return $value
        }

        Warn "Enter a number between $Minimum and $Maximum."
    }
}

function Prompt-YesNoWithDefault([string]$Prompt, [bool]$Default) {
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }

    while ($true) {
        $response = Read-Host "$Prompt [$hint]"
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $Default
        }

        switch ($response.Trim().ToLowerInvariant()) {
            'y' { return $true }
            'yes' { return $true }
            'n' { return $false }
            'no' { return $false }
            default { Warn "Enter yes or no." }
        }
    }
}

function Quote-ServiceCommandArg([string]$Value) {
    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0

    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $backslashes++
            continue
        }

        if ($ch -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }

        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }

        [void]$builder.Append($ch)
    }

    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }

    [void]$builder.Append('"')
    $builder.ToString()
}

function Build-ServiceBinaryPath([string]$ExePath, [string]$ConfigPath, [string]$Name, [string]$LogPath) {
    @(
        (Quote-ServiceCommandArg $ExePath)
        '--run-windows-service'
        '--service-name'
        (Quote-ServiceCommandArg $Name)
        '-c'
        (Quote-ServiceCommandArg $ConfigPath)
        '--log-file'
        (Quote-ServiceCommandArg $LogPath)
    ) -join ' '
}

function Install-ServiceBinary([string]$SourcePath, [string]$DestinationDir) {
    $DestinationDir = [Environment]::ExpandEnvironmentVariables($DestinationDir)
    if ([string]::IsNullOrWhiteSpace($DestinationDir)) {
        throw "Binary install directory cannot be empty."
    }

    if (-not (Test-Path $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        OK "Created $DestinationDir"
    }

    $destinationPath = Join-Path $DestinationDir (Split-Path $SourcePath -Leaf)
    $sourceFullPath = [System.IO.Path]::GetFullPath($SourcePath)
    $destinationFullPath = [System.IO.Path]::GetFullPath($destinationPath)

    if ($sourceFullPath.Equals($destinationFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $sourceFullPath
    }

    Copy-Item -LiteralPath $sourceFullPath -Destination $destinationFullPath -Force
    return $destinationFullPath
}

function Read-BigEndianUInt32([byte[]]$Bytes, [ref]$Offset) {
    if (($Offset.Value + 4) -gt $Bytes.Length) {
        throw "unexpected end of OpenSSH key data"
    }

    $value =
        ($Bytes[$Offset.Value] -shl 24) -bor
        ($Bytes[$Offset.Value + 1] -shl 16) -bor
        ($Bytes[$Offset.Value + 2] -shl 8) -bor
        $Bytes[$Offset.Value + 3]
    $Offset.Value += 4
    return [uint32]$value
}

function Read-OpenSshString([byte[]]$Bytes, [ref]$Offset) {
    $length = [int](Read-BigEndianUInt32 $Bytes $Offset)
    if (($Offset.Value + $length) -gt $Bytes.Length) {
        throw "unexpected end of OpenSSH key data"
    }

    $value = [System.Text.Encoding]::ASCII.GetString($Bytes, $Offset.Value, $length)
    $Offset.Value += $length
    return $value
}

function Get-OpenSshPrivateKeyCipherName([string]$Path) {
    try {
        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
        if (-not $lines -or $lines[0] -ne '-----BEGIN OPENSSH PRIVATE KEY-----') {
            return $null
        }

        $base64 = ($lines | Where-Object { $_ -notmatch '^-----' }) -join ''
        $bytes = [Convert]::FromBase64String($base64)
        $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 15)
        if ($magic -ne "openssh-key-v1`0") {
            return $null
        }

        $offset = 15
        return Read-OpenSshString $bytes ([ref]$offset)
    } catch {
        return $null
    }
}

function Assert-UnencryptedHostKey([string]$Path) {
    $cipherName = Get-OpenSshPrivateKeyCipherName $Path
    if ($cipherName -and $cipherName -ne 'none') {
        throw (
            "Host key '$Path' is encrypted (cipher '$cipherName'). " +
            "narrowd requires an unencrypted host key. " +
            "If this file was created by an older installer run, rerun Install-Narrowd.ps1 with -Force to regenerate it."
        )
    }
}

function Remove-ExistingService([string]$Name) {
    $existing = Get-Service $Name -ErrorAction SilentlyContinue
    if (-not $existing) { return }

    if ($existing.Status -ne 'Stopped') {
        try {
            Stop-Service -Name $Name -Force -ErrorAction Stop
            $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        } catch {
            Warn "Failed to stop existing service cleanly: $($_.Exception.Message)"
        }
    }

    & sc.exe delete $Name | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        if (-not (Get-Service $Name -ErrorAction SilentlyContinue)) {
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

function Grant-LogOnAsService([string]$Account) {
    if (-not ([System.Management.Automation.PSTypeName]'NarrowdLsa').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class NarrowdLsa {
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES {
        public int Length, Attributes;
        public IntPtr RootDirectory, ObjectName, SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING {
        public ushort Length, MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
    }

    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attrs,
                                     int access, out IntPtr handle);

    [DllImport("advapi32", SetLastError = true)]
    static extern uint LsaAddAccountRights(IntPtr policy, IntPtr sid,
                                           LSA_UNICODE_STRING[] rights, int count);

    [DllImport("advapi32")]
    static extern uint LsaClose(IntPtr handle);

    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupAccountName(string system, string name,
                                         IntPtr sid, ref int cbSid,
                                         StringBuilder domain, ref int cbDomain, out int use);

    const int POLICY_ALL_ACCESS = 0xF0FFF;

    public static void AddRight(string account, string right) {
        int sidSz = 0, domSz = 256, use;
        var dom = new StringBuilder(domSz);
        LookupAccountName(null, account, IntPtr.Zero, ref sidSz, dom, ref domSz, out use);

        var sid = Marshal.AllocHGlobal(sidSz);
        try {
            if (!LookupAccountName(null, account, sid, ref sidSz, dom, ref domSz, out use))
                throw new Win32Exception();

            var attrs = new LSA_OBJECT_ATTRIBUTES();
            IntPtr pol;
            if (LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_ALL_ACCESS, out pol) != 0)
                throw new Exception("LsaOpenPolicy failed");
            try {
                var rights = new LSA_UNICODE_STRING[1];
                rights[0].Buffer = right;
                rights[0].Length = (ushort)(right.Length * 2);
                rights[0].MaximumLength = (ushort)(rights[0].Length + 2);
                if (LsaAddAccountRights(pol, sid, rights, 1) != 0)
                    throw new Exception("LsaAddAccountRights failed");
            } finally {
                LsaClose(pol);
            }
        } finally {
            Marshal.FreeHGlobal(sid);
        }
    }
}
'@
    }

    [NarrowdLsa]::AddRight($Account, 'SeServiceLogonRight')
}

$defaultUserName = Get-DefaultUserName
$defaultBinaryPath = Get-DefaultBinaryPath
if (-not $PSBoundParameters.ContainsKey('UserName')) {
    $UserName = Prompt-WithDefault 'Windows account for the service' $defaultUserName
}

if (-not $PSBoundParameters.ContainsKey('BinaryPath')) {
    $BinaryPath = Prompt-WithDefault 'Path to narrowd.exe' $defaultBinaryPath
}

if (-not $PSBoundParameters.ContainsKey('Port')) {
    $Port = Prompt-IntWithDefault 'TCP port to listen on' 2222 1 65535
}

if (-not $PSBoundParameters.ContainsKey('ServiceName')) {
    $ServiceName = Prompt-WithDefault 'Windows service name' 'narrowd'
}

if (-not $PSBoundParameters.ContainsKey('NoBinaryCopy')) {
    $NoBinaryCopy = -not (Prompt-YesNoWithDefault 'Copy narrowd.exe to a stable install directory?' $true)
}

if (-not $PSBoundParameters.ContainsKey('Force')) {
    $Force = Prompt-YesNoWithDefault 'Reinstall existing service if present?' $false
}

if (-not $PSBoundParameters.ContainsKey('NoFirewall')) {
    $NoFirewall = Prompt-YesNoWithDefault 'Skip creating the inbound firewall rule?' $false
}

Step "Validating"
$BinaryPath = [Environment]::ExpandEnvironmentVariables($BinaryPath)
if (-not (Test-Path $BinaryPath)) {
    throw (
        "Cannot find narrowd.exe at '$BinaryPath'. " +
        "Build it with 'cargo build --release' or pass -BinaryPath explicitly."
    )
}

$BinaryPath = (Resolve-Path $BinaryPath -ErrorAction Stop).Path
OK "UserName: $UserName"
OK "Binary: $BinaryPath"
OK "Port: $Port"
OK "Service name: $ServiceName"

$accountFqn = if ($UserName -match '\\') { $UserName } else { ".\$UserName" }

Step "Resolving profile for '$UserName'"
$profileDir = Resolve-ProfilePath $UserName
$narrowdDir = Get-DefaultNarrowdRoot $profileDir
$configFile = Join-Path $narrowdDir 'narrowd.conf'
$hostKeyFile = Join-Path $narrowdDir 'ssh_host_ed25519_key'
$authKeysFile = Join-Path $profileDir '.ssh\authorized_keys'
$logDir = Join-Path $narrowdDir 'logs'
$serviceLogFile = Join-Path $logDir 'narrowd.log'
OK "Profile: $profileDir"
OK "Data directory: $narrowdDir"

if (-not $NoBinaryCopy) {
    if (-not $PSBoundParameters.ContainsKey('BinaryInstallDir')) {
        $BinaryInstallDir = Prompt-WithDefault 'Binary install directory' (Get-DefaultBinaryInstallDir $profileDir)
    }
    $BinaryInstallDir = [Environment]::ExpandEnvironmentVariables($BinaryInstallDir)
    OK "Binary install directory: $BinaryInstallDir"
} else {
    OK "Binary copy: disabled"
}

Step "Creating directories"
foreach ($dir in @($narrowdDir, $logDir, (Split-Path $authKeysFile -Parent))) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        OK "Created $dir"
    }
}

Step "SSH host key"
if ((Test-Path $hostKeyFile) -and -not $Force) {
    Assert-UnencryptedHostKey $hostKeyFile
    OK "Already exists - skipping (use -Force to regenerate)"
} else {
    $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $keygen) {
        throw (
            "ssh-keygen not found. " +
            "Install the OpenSSH Client optional feature in Windows Settings."
        )
    }

    Remove-Item "$hostKeyFile", "$hostKeyFile.pub" -Force -ErrorAction SilentlyContinue
    & ssh-keygen -t ed25519 -f $hostKeyFile -N '""' -q
    if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed (exit $LASTEXITCODE)" }
    Assert-UnencryptedHostKey $hostKeyFile
    OK $hostKeyFile
}

$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)

$svcSid = (New-Object Security.Principal.NTAccount($accountFqn)).Translate(
    [Security.Principal.SecurityIdentifier]
)
$adminSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'

$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $svcSid, 'Read', 'None', 'None', 'Allow'
)))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $adminSid, 'FullControl', 'None', 'None', 'Allow'
)))

Set-Acl -Path $hostKeyFile -AclObject $acl
OK "Host key permissions set"

Step "Writing config: $configFile"
if ((Test-Path $configFile) -and -not $Force) {
    Warn "Config already exists - skipping (use -Force to overwrite)"
} else {
    $hk = $hostKeyFile -replace '\\', '/'
    $ak = $authKeysFile -replace '\\', '/'
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $configContent = (
        @(
            "# narrowd config - managed by Install-Narrowd.ps1"
            "# Daemon runs as: $accountFqn"
            "# All paths are absolute so they work correctly inside a Windows service."
            ''
            "Port $Port"
            'ListenAddress 0.0.0.0'
            ''
            "HostKey $hk"
            "AuthorizedKeysFile $ak"
            ''
            'Shell powershell.exe'
            'PermitTTY yes'
            'PermitExec yes'
            ''
            'Subsystem sftp internal-sftp'
            'AllowTcpForwarding yes'
            'AllowRemoteForwarding yes'
            'GatewayPorts yes'
            ''
            '# --- public-exposure hardening ---'
            'MaxUnauthConnectionsGlobal 16'
            'MaxUnauthConnectionsPerIp 3'
            'MaxUnauthConnectionsPerSubnet 8'
            'NewConnectionsPerMinutePerIp 12'
            'NewConnectionsBurstPerIp 4'
            'LoginGraceTime 15s'
            'ClientBannerTimeout 5s'
            'KexStartTimeout 5s'
            'MaxAuthAttempts 4'
            'AuthRejectionTime 2s'
            'AuthFailureBanThreshold 8'
            'AuthFailureBanWindow 10m'
            'AuthFailureBanDuration 15m'
            'InactivityTimeout 15m'
            'KeepaliveInterval 30s'
            'KeepaliveMax 3'
            ''
            'LogLevel info'
        ) -join [Environment]::NewLine
    ) + [Environment]::NewLine

    [System.IO.File]::WriteAllText($configFile, $configContent, $utf8NoBom)
    OK $configFile
}

if (-not (Test-Path $authKeysFile)) {
    Warn "authorized_keys not found - create it before connecting:"
    Warn "  $authKeysFile"
    Warn "  (for example copy your public key into that file)"
}

Step "Setting log directory permissions"
$logAcl = Get-Acl $logDir
$logRule = New-Object Security.AccessControl.FileSystemAccessRule(
    $svcSid,
    'Modify',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow'
)
$logAcl.AddAccessRule($logRule)
Set-Acl $logDir $logAcl
OK "Write access granted to $accountFqn on $logDir"

Step "Granting 'Log on as a service' right"
Grant-LogOnAsService $UserName
OK "SeServiceLogonRight granted to $UserName"

Write-Host ""
$credential = Get-Credential -UserName $accountFqn `
    -Message "Enter the Windows password for '$accountFqn' (stored by Windows for the service logon):"

Step "Installing service '$ServiceName'"
$existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Force) {
        throw "Service '$ServiceName' already exists. Use -Force to reinstall."
    }
    Write-Host "    Removing existing service..."
    Remove-ExistingService $ServiceName
}

$serviceExePath = $BinaryPath
if (-not $NoBinaryCopy) {
    Step "Deploying binary"
    $serviceExePath = Install-ServiceBinary `
        -SourcePath $BinaryPath `
        -DestinationDir $BinaryInstallDir
    OK "Service binary: $serviceExePath"
}

$serviceBinaryPath = Build-ServiceBinaryPath `
    -ExePath $serviceExePath `
    -ConfigPath $configFile `
    -Name $ServiceName `
    -LogPath $serviceLogFile

New-Service `
    -Name $ServiceName `
    -BinaryPathName $serviceBinaryPath `
    -DisplayName $ServiceName `
    -Description "narrowd single-user SSH daemon" `
    -StartupType Automatic `
    -Credential $credential | Out-Null
OK "Service '$ServiceName' installed"

if (-not $NoFirewall) {
    Step "Adding inbound firewall rule (TCP $Port)"
    $ruleName = "narrowd SSH (port $Port)"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $Port `
        -Action Allow `
        -Profile Any | Out-Null
    OK "Rule '$ruleName' added"
}

Step "Starting service"
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    OK "Service is Running"
} else {
    $status = if ($svc) { $svc.Status } else { 'not found' }
    Warn "Service status: $status"
    Warn "Check logs: $serviceLogFile"
    Warn "Or run:     Get-Service $ServiceName"
}

$bar = '=' * 54
Write-Host ""
Write-Host $bar -ForegroundColor Green
Write-Host " narrowd installed" -ForegroundColor Green
Write-Host $bar -ForegroundColor Green
Write-Host ""
Write-Host ("  Service name : " + $ServiceName)
Write-Host ("  Runs as      : " + $accountFqn)
Write-Host ("  Service exe  : " + $serviceExePath)
Write-Host ("  Listen port  : " + $Port)
Write-Host ("  Config       : " + $configFile)
Write-Host ("  Host key     : " + $hostKeyFile)
Write-Host ("  Auth keys    : " + $authKeysFile)
Write-Host ("  Logs         : " + $serviceLogFile)
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Add your SSH public key:"
Write-Host "       $authKeysFile"
Write-Host "  2. Test the connection:"
Write-Host "       ssh -p $Port $UserName@localhost"
Write-Host "  3. Manage the service:"
Write-Host "       Get-Service     $ServiceName"
Write-Host "       Stop-Service    $ServiceName"
Write-Host "       Restart-Service $ServiceName"
Write-Host ""
