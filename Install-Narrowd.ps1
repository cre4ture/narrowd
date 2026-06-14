#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs narrowd as a Windows service running as the specified user account.

.DESCRIPTION
    narrowd is a single-user SSH daemon — it runs AS the target user, so all SSH
    sessions carry exactly that user's file-system and process rights without any
    impersonation layer.

    This script:
      - Resolves the user's Windows profile directory
      - Generates an ed25519 SSH host key (requires OpenSSH Client optional feature)
      - Writes a narrowd config with absolute paths (avoids ~ expansion issues in services)
      - Locks the host key to the service account (read-only) and Administrators (full)
      - Grants "Log on as a service" to the account via the LSA policy API
      - Installs and configures the service via NSSM
      - Adds an inbound Windows Firewall rule for the chosen port

    Requires NSSM on PATH, or specify -NssmPath.
    Download NSSM: https://nssm.cc/download
    Install OpenSSH Client: Settings > System > Optional Features > OpenSSH Client

.PARAMETER UserName
    Windows account that owns all SSH sessions (e.g. "alice" or "DOMAIN\alice").
    The daemon runs AS this account — no extra privilege is granted.

.PARAMETER BinaryPath
    Full path to narrowd.exe.

.PARAMETER Port
    TCP port narrowd listens on. Default: 2222.

.PARAMETER ServiceName
    Windows service name. Default: narrowd.

.PARAMETER NssmPath
    Path to nssm.exe. Searched on PATH if omitted.

.PARAMETER Force
    Remove and reinstall an existing service, overwrite an existing config.

.PARAMETER NoFirewall
    Skip creating the inbound firewall rule.

.EXAMPLE
    .\Install-Narrowd.ps1 -UserName alice -BinaryPath "C:\Tools\narrowd\narrowd.exe"

.EXAMPLE
    .\Install-Narrowd.ps1 -UserName alice -BinaryPath "C:\Tools\narrowd\narrowd.exe" -Port 22 -Force
#>

param(
    [Parameter(Mandatory)]
    [string]$UserName,

    [Parameter(Mandatory)]
    [string]$BinaryPath,

    [ValidateRange(1, 65535)]
    [int]$Port = 2222,

    [string]$ServiceName = 'narrowd',

    [string]$NssmPath = '',

    [switch]$Force,

    [switch]$NoFirewall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── helpers ───────────────────────────────────────────────────────────────────

function Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function OK([string]$msg)   { Write-Host "    ok  $msg" -ForegroundColor Green }
function Warn([string]$msg) { Write-Host "    WARN $msg" -ForegroundColor Yellow }

function Find-Nssm {
    if ($NssmPath -and (Test-Path $NssmPath)) { return $NssmPath }
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw @"
nssm.exe not found.
  Download from: https://nssm.cc/download
  Then place nssm.exe on PATH or pass -NssmPath "C:\path\to\nssm.exe".
"@
}

function Resolve-ProfilePath([string]$Name) {
    # Strip domain prefix if present (DOMAIN\user -> user)
    $bare = $Name -replace '^.*\\', ''

    # WMI lookup works for accounts that have a local profile
    $profile = Get-WmiObject Win32_UserProfile `
        -Filter "LocalPath LIKE '%\\$bare'" -ErrorAction SilentlyContinue |
        Sort-Object -Property LastUseTime -Descending |
        Select-Object -First 1 -ExpandProperty LocalPath
    if ($profile) { return $profile }

    # Fallback: C:\Users\<bare>
    $fallback = "C:\Users\$bare"
    if (Test-Path $fallback) { return $fallback }

    throw (
        "Cannot locate Windows profile for '$Name'. " +
        "Ensure the account exists and has logged in at least once, " +
        "or create C:\Users\$bare manually."
    )
}

# Grants SeServiceLogonRight via the Win32 LSA API — no external tools required.
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
        public int    Length, Attributes;
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
                rights[0].Buffer        = right;
                rights[0].Length        = (ushort)(right.Length * 2);
                rights[0].MaximumLength = (ushort)(rights[0].Length + 2);
                if (LsaAddAccountRights(pol, sid, rights, 1) != 0)
                    throw new Exception("LsaAddAccountRights failed");
            } finally { LsaClose(pol); }
        } finally { Marshal.FreeHGlobal(sid); }
    }
}
'@
    }
    [NarrowdLsa]::AddRight($Account, 'SeServiceLogonRight')
}

# ── validate inputs ───────────────────────────────────────────────────────────

Step "Validating"
$BinaryPath = (Resolve-Path $BinaryPath -ErrorAction Stop).Path
OK "Binary: $BinaryPath"

$nssm = Find-Nssm
OK "NSSM: $nssm"

# Determine fully-qualified account name for NSSM (.\user for local, DOMAIN\user as-is)
$accountFqn = if ($UserName -match '\\') { $UserName } else { ".\$UserName" }

# ── resolve user profile ──────────────────────────────────────────────────────

Step "Resolving profile for '$UserName'"
$profileDir  = Resolve-ProfilePath $UserName
$appdataDir  = Join-Path $profileDir "AppData\Roaming"
$narrowdDir  = Join-Path $appdataDir "narrowd"
$configFile  = Join-Path $narrowdDir "narrowd.conf"
$hostKeyFile = Join-Path $narrowdDir "ssh_host_ed25519_key"
$authKeysFile= Join-Path $profileDir ".ssh\authorized_keys"
$logDir      = Join-Path $narrowdDir "logs"
OK "Profile: $profileDir"

# ── create directories ────────────────────────────────────────────────────────

Step "Creating directories"
foreach ($dir in @($narrowdDir, $logDir, (Split-Path $authKeysFile -Parent))) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        OK "Created $dir"
    }
}

# ── SSH host key ──────────────────────────────────────────────────────────────

Step "SSH host key"
if ((Test-Path $hostKeyFile) -and -not $Force) {
    OK "Already exists — skipping (use -Force to regenerate)"
} else {
    $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $keygen) {
        throw (
            "ssh-keygen not found. " +
            "Install it via: Settings > System > Optional Features > OpenSSH Client"
        )
    }
    # Remove old key pair if regenerating
    Remove-Item "$hostKeyFile", "$hostKeyFile.pub" -Force -ErrorAction SilentlyContinue

    & ssh-keygen -t ed25519 -f $hostKeyFile -N "" -q
    if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed (exit $LASTEXITCODE)" }
    OK $hostKeyFile
}

# Restrict host key: service account read-only, Administrators full control
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)   # disable ACL inheritance

$svcSid   = (New-Object Security.Principal.NTAccount($accountFqn)).Translate(
                [Security.Principal.SecurityIdentifier])
$adminSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'

$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $svcSid,   'Read',        'None', 'None', 'Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
    $adminSid, 'FullControl', 'None', 'None', 'Allow')))

Set-Acl -Path $hostKeyFile -AclObject $acl
OK "Host key permissions set"

# ── config file ───────────────────────────────────────────────────────────────

Step "Writing config: $configFile"
if ((Test-Path $configFile) -and -not $Force) {
    Warn "Config already exists — skipping (use -Force to overwrite)"
} else {
    # Absolute paths with forward slashes (Rust accepts them on Windows)
    $hk = $hostKeyFile  -replace '\\', '/'
    $ak = $authKeysFile -replace '\\', '/'

    # Write with UTF-8 (no BOM) so narrowd can read it
    $configContent = @"
# narrowd config — managed by Install-Narrowd.ps1
# Daemon runs as: $accountFqn
# All paths are absolute so they work correctly inside a Windows service.

Port $Port
ListenAddress 0.0.0.0

HostKey $hk
AuthorizedKeysFile $ak

Shell powershell.exe
PermitTTY yes
PermitExec yes

Subsystem sftp internal-sftp
AllowTcpForwarding yes
AllowRemoteForwarding yes
GatewayPorts yes

# --- public-exposure hardening ---
MaxUnauthConnectionsGlobal 16
MaxUnauthConnectionsPerIp 3
MaxUnauthConnectionsPerSubnet 8
NewConnectionsPerMinutePerIp 12
NewConnectionsBurstPerIp 4
LoginGraceTime 15s
ClientBannerTimeout 5s
KexStartTimeout 5s
MaxAuthAttempts 4
AuthRejectionTime 2s
AuthFailureBanThreshold 8
AuthFailureBanWindow 10m
AuthFailureBanDuration 15m
InactivityTimeout 15m
KeepaliveInterval 30s
KeepaliveMax 3

LogLevel info
"@
    [System.IO.File]::WriteAllText($configFile, $configContent,
        [System.Text.Encoding]::UTF8)
    OK $configFile
}

# ── authorized_keys reminder ──────────────────────────────────────────────────

if (-not (Test-Path $authKeysFile)) {
    Warn "authorized_keys not found — create it before connecting:"
    Warn "  $authKeysFile"
    Warn "  (e.g. copy your public key into that file)"
}

# ── log directory ACL — service account needs write access ───────────────────

Step "Setting log directory permissions"
$logAcl  = Get-Acl $logDir
$logRule = New-Object Security.AccessControl.FileSystemAccessRule(
    $svcSid, 'Modify',
    'ContainerInherit,ObjectInherit', 'None', 'Allow')
$logAcl.AddAccessRule($logRule)
Set-Acl $logDir $logAcl
OK "Write access granted to $accountFqn on $logDir"

# ── Log on as a service ───────────────────────────────────────────────────────

Step "Granting 'Log on as a service' right"
Grant-LogOnAsService $UserName
OK "SeServiceLogonRight granted to $UserName"

# ── password prompt ───────────────────────────────────────────────────────────

Write-Host ""
$credential = Get-Credential -UserName $accountFqn `
    -Message "Enter the Windows password for '$accountFqn' (stored by NSSM to start the service):"
$bstr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
$plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

# ── NSSM service ──────────────────────────────────────────────────────────────

Step "Installing service '$ServiceName'"
$existing = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if (-not $Force) {
        throw "Service '$ServiceName' already exists. Use -Force to reinstall."
    }
    Write-Host "    Removing existing service..."
    & $nssm stop   $ServiceName 2>&1 | Out-Null
    & $nssm remove $ServiceName confirm 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

& $nssm install $ServiceName $BinaryPath
& $nssm set $ServiceName AppParameters  "-c `"$configFile`""
& $nssm set $ServiceName AppDirectory   (Split-Path $BinaryPath -Parent)
& $nssm set $ServiceName ObjectName     $accountFqn $plainPw
& $nssm set $ServiceName Start          SERVICE_AUTO_START
& $nssm set $ServiceName AppStdout      (Join-Path $logDir "narrowd.log")
& $nssm set $ServiceName AppStderr      (Join-Path $logDir "narrowd-error.log")
& $nssm set $ServiceName AppRotateFiles      1
& $nssm set $ServiceName AppRotateBytes      10485760   # 10 MB
& $nssm set $ServiceName AppRotateOnline     1
& $nssm set $ServiceName Description    "narrowd single-user SSH daemon"

# Clear plain-text password from memory
$plainPw = $null

OK "Service '$ServiceName' installed"

# ── firewall ──────────────────────────────────────────────────────────────────

if (-not $NoFirewall) {
    Step "Adding inbound firewall rule (TCP $Port)"
    $ruleName = "narrowd SSH (port $Port)"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction   Inbound `
        -Protocol    TCP `
        -LocalPort   $Port `
        -Action      Allow `
        -Profile     Any | Out-Null
    OK "Rule '$ruleName' added"
}

# ── start ─────────────────────────────────────────────────────────────────────

Step "Starting service"
& $nssm start $ServiceName
Start-Sleep -Seconds 3
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    OK "Service is Running"
} else {
    $status = if ($svc) { $svc.Status } else { "not found" }
    Warn "Service status: $status"
    Warn "Check logs: $logDir"
    Warn "Or run:     & '$nssm' status $ServiceName"
}

# ── summary ───────────────────────────────────────────────────────────────────

$bar = "=" * 54
Write-Host ""
Write-Host $bar -ForegroundColor Green
Write-Host " narrowd installed" -ForegroundColor Green
Write-Host $bar -ForegroundColor Green
Write-Host ""
Write-Host ("  Service name : " + $ServiceName)
Write-Host ("  Runs as      : " + $accountFqn)
Write-Host ("  Listen port  : " + $Port)
Write-Host ("  Config       : " + $configFile)
Write-Host ("  Host key     : " + $hostKeyFile)
Write-Host ("  Auth keys    : " + $authKeysFile)
Write-Host ("  Logs         : " + $logDir)
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Add your SSH public key:"
Write-Host "       $authKeysFile"
Write-Host "  2. Test the connection:"
Write-Host "       ssh -p $Port $UserName@localhost"
Write-Host "  3. Manage the service:"
Write-Host "       nssm status  $ServiceName"
Write-Host "       nssm stop    $ServiceName"
Write-Host "       nssm restart $ServiceName"
Write-Host ""
