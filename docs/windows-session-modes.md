# Windows session modes

`narrowd` currently has two different Windows deployment modes because Windows
draws a hard line between machine services in Session 0 and processes that run
inside a signed-in user's interactive session.

This document explains why both modes exist, what each one is for, and how
automatic logon fits in when you want the user-session variant to come up on
its own after boot.

## Overview

| Mode | How it starts | Runs in | Best for | Main limitation |
| --- | --- | --- | --- | --- |
| Native Windows service | Service Control Manager at boot | Session 0 | Headless or always-on service scenarios | No interactive user session context |
| MSIX user-session launcher | Packaged per-user startup task at user logon | Signed-in user's session | Cases that need normal user-session behavior | Does not start until that user has logged in |

## 1. Native Windows service in Session 0

Install path:

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File .\Install-Narrowd.ps1
```

This mode installs `narrowd` as a regular Windows service. It is the right fit
when you want the daemon to start with the machine, regardless of whether any
user has signed in yet.

Typical reasons to choose it:

- the machine should accept SSH connections immediately after boot
- the host is effectively headless or administered remotely
- you want service-style startup and recovery behavior from the Service Control Manager

Why this mode exists:

- Windows services run in Session 0, which is isolated from interactive desktop sessions
- that makes the daemon independent from any foreground user logon
- it also means the process does not get a normal interactive user-session environment

Practical consequences of Session 0:

- no access to the signed-in user's desktop session
- no automatic access to per-user session state that only exists after logon
- features that depend on a real interactive user session are a bad fit here

For the relevant Windows background, see Microsoft's documentation on
[Session 0 isolation](https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista)
and
[interactive services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services).

## 2. MSIX launcher in the signed-in user session

Install path:

```powershell
powershell -ExecutionPolicy Bypass -File .\Build-NarrowdMsix.ps1
powershell -ExecutionPolicy Bypass -File .\Install-NarrowdMsix.ps1
```

This mode packages `narrowd-session-launcher.exe` as an MSIX app and registers
a per-user startup task. After that user signs in, Windows starts the launcher
inside that same user session.

Typical reasons to choose it:

- `narrowd` should run with the normal environment of the signed-in user
- the daemon should use that user's profile, `%LOCALAPPDATA%`, and session-scoped state
- Session 0 restrictions are the wrong fit for the workload you want to expose over SSH

Why this mode exists:

- Windows startup tasks for packaged desktop apps run at user logon, not in Session 0
- that gives `narrowd` the same user-session context that a normal desktop process would have
- it avoids the service-side limitations that come from Session 0 isolation

Practical consequences:

- `narrowd` does not start until the target user has actually logged in
- signing out ends that user session, so this mode is tied to user logon state
- this is the better fit when the daemon should behave like a user-session process, not like a machine service

The current package manifest uses a packaged desktop
[`desktop:StartupTask`](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-startuptask)
to register that auto-start behavior.

## 3. If you want the user session automatically after boot

The MSIX mode solves "start `narrowd` inside a real user session after logon".
It does not create the user logon by itself.

If your goal is:

- boot the machine
- automatically sign in a dedicated local user
- then have `narrowd` come up inside that user's session

then Windows needs an actual automatic logon configuration. The simplest
supported options are:

- Windows `AutoAdminLogon`
- Sysinternals [Autologon](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)

Microsoft documents the built-in mechanism here:
[Configure Windows to automate logon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon).

In that setup, the pieces line up like this:

1. Windows boots.
2. Windows automatically signs in the dedicated user account.
3. The MSIX startup task runs in that newly created user session.
4. `narrowd-session-launcher.exe` starts `narrowd` with the user's own session context.

This is the closest thing to "automatically create the user session and then
run the user-session variant of narrowd".

Tradeoffs and cautions:

- automatic logon changes the security posture of the machine
- the account is intentionally signed in after boot, so this is best suited to dedicated or physically controlled systems
- use a dedicated account for `narrowd`, not an all-purpose administrator desktop account
- if the user signs out, the session-backed `narrowd` instance goes away until the next logon

## Choosing between them

Choose the native Windows service when:

- machine boot should be enough to bring up SSH
- no interactive user session is required
- the host behaves more like a server than a personal workstation

Choose the MSIX user-session mode when:

- the daemon should live in the real signed-in user session
- Session 0 limitations are the problem you are trying to avoid
- per-user startup after logon is acceptable

Choose MSIX plus automatic logon when:

- you specifically need a real user session to exist automatically after boot
- you accept the operational and security tradeoffs of automatic sign-in
