# WindowsHardening

The BYU CCDC Windows hardening module. It provides OS detection, user/password
management, firewall configuration, service hardening, and SMB/WDigest
protection for both Active Directory domain controllers and local
(workstation/member) machines.

- **PowerShell 5.1 compatible** for deployment on stock Windows PowerShell 5.1.
- **Scriptable.** Every interactive prompt has a `-Parameter` and/or `-Force`
  equivalent.
- **Backup/restore (experimental).** `Backup-WindowsState` / `Restore-WindowsState`
  capture and restore machine state.

---

## Table of Contents

- [Installation](#installation)
- [Module Layout](#module-layout)
- [Quick Start](#quick-start)
- [Functions](#functions)
- [Parameters and Aliases](#parameters-and-aliases)
- [Backup and Restore](#backup-and-restore)
- [PS 5.1 Compatibility](#ps-51-compatibility)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Installation

```powershell
# From the project root
Import-Module ./WindowsHardening -Force

# Or specify the absolute/module path
Import-Module "C:\path\to\WindowsHardening" -Force

# List everything the module exports
Get-Command -Module WindowsHardening | Sort-Object Name
```

> The manifest declares `PowerShellVersion = '5.1'`. The module runs on
> Windows 10, Windows 11, and Windows Server 2016/2019/2022/2025.

---

## Module Layout

Every function is exported. Files are grouped by purpose:

```
WindowsHardening/
├── WindowsHardening.psd1 / .psm1
├── Public/
│   ├── Invoke-WindowsHardening.ps1, Invoke-HardeningMenu.ps1, Start-QuickHarden.ps1
│   ├── Users/       Invoke-UserHardening, Set-ZuluPassword, Set-UserPassword,
│   │                Initialize-CompetitionUsers, New-ADUserAccount, Remove-AdminUsers,
│   │                Remove-RDPUsers, Add-RDPUsers, Protect-Mimikatz
│   ├── Network/     Invoke-NetworkHardening, Set-FirewallConfiguration, Remove-RemoteManagement
│   ├── Services/    Invoke-ServiceHardening, Disable-UnusedNetworkProtocols, Update-SMB,
│   │                Set-RestrictedExecutionPolicy
│   ├── SIEM/        Install-Splunk
│   ├── Patching/    Install-EternalBluePatch
│   ├── Messages/    Write-Log, Show-OperationSummary, Start-HardeningLog, Read-YesNo,
│   │                Read-CommaList, Read-SecretInput
│   ├── Helpers/     Initialize-System, Initialize-Context, Get-HardeningContext,
│   │                Test-Prerequisites, Test-IsDomainController, Get-OperatingSystemInfo,
│   │                Invoke-HardeningOperation, Set-RegistryValue, Get-FileFromUrl,
│   │                Show-Users, New-Password
│   └── Inject/
├── Data/            ports.json, patchURLs.json, wordlist.txt, advancedAuditing.ps1
└── Dev/             Experimental: Backup-WindowsState, Restore-WindowsState + helpers
```

Data files are read from `Data/`, so the module works from any directory and
without internet access; setup downloads a file from GitHub only if it is
missing. Output goes to the log directory (`-LogPath`, default
`C:\Windows\Logs\Hardening`): the run log, the firewall backup (`fwback.wfw`),
and Zulu's `zulu.log` / `users_zulu.csv`. Errors from a `Invoke-WindowsHardening`
run are also appended to `Desktop\hard.txt`.

Aliases: `Configure-Firewall` → `Set-FirewallConfiguration`, `Patch-Mimikatz` →
`Protect-Mimikatz`, `Upgrade-SMB` → `Update-SMB`. Previous function names still
work as aliases: `New-Zulu-Integration`/`New-ZuluIntegration` → `Set-ZuluPassword`,
`Harden-Users`/`-Network`/`-Services` → `Invoke-UserHardening`/`Invoke-NetworkHardening`/
`Invoke-ServiceHardening`, `Disable-UnnecessaryServices` → `Disable-UnusedNetworkProtocols`,
`Revert-WindowsState` → `Restore-WindowsState`, `Print-Users` → `Show-Users`,
`Print-Log` → `Show-OperationSummary`.

Many functions read the shared hardening context (DC status, OS, salt phrase,
log path). Setup (`Initialize-System`) runs automatically the first time a
hardening step runs in a session, so functions can be called on their own. It
detects whether the machine is a domain controller (NTDS service present); run
`Initialize-System -Force` to start over with a new log file.
`Get-HardeningContext` shows what the module detected.

---

## Quick Start

The simplest path is the main entry point in **non-interactive** mode:

```powershell
Import-Module ./WindowsHardening -Force

# Run the full quick-hardening sequence (domain controller vs. local is auto-detected)
Invoke-WindowsHardening -QuickHarden

# Same, but keep WinRM reachable during the run (e.g. applied over a remote session)
Invoke-WindowsHardening -QuickHarden -PreserveManagementPort

# Skip password change and RDP-user reset
Invoke-WindowsHardening -QuickHarden -SkipPasswordChange -SkipRDP

# Interactive menu mode
Invoke-WindowsHardening
```

Optionally take a backup first (experimental):

```powershell
$backup = Backup-WindowsState
# ...harden...
Restore-WindowsState -BackupPath $backup.Path
```

---

## Functions

The main functions below show **interactive** (prompt-driven) and
**non-interactive** (parameter/`-Force`-driven) usage. Use `Get-Help <name>` for
the rest.

### `Add-RDPUsers`

Adds users to the `Remote Desktop Users` group. Without parameters it prompts
for a count and usernames; non-interactive it takes `-Users`.

```powershell
# Interactive
Add-RDPUsers

# Non-interactive
Add-RDPUsers -Users ccdcuser1,ccdcuser2 -Force
```

### `Backup-WindowsState` (experimental)

Captures full machine state (see [Backup and Restore](#backup-and-restore)).
Always non-interactive. Returns an object with the created backup directory.

```powershell
$backup = Backup-WindowsState
$backup.Path                         # C:\Windows\System32\wbem\.hb\2026-08-26_120000

# Override the storage location
$backup = Backup-WindowsState -BackupPath "D:\backups\machine1"
```

### `Disable-UnusedNetworkProtocols`

Disables IPv6 on active adapters and NetBIOS over TCP/IP on IP-enabled
adapters. No prompts. (Formerly `Disable-UnnecessaryServices`.)

```powershell
# Same in both modes (no parameters exist)
Disable-UnusedNetworkProtocols
```

### `Get-HardeningContext`

Returns what the module currently knows about the machine: DC status, OS, log
path, salt phrase, and so on. Populated by `Initialize-System`, which runs
automatically on the first hardening step.

```powershell
Initialize-System
Get-HardeningContext
```

### `Install-EternalBluePatch`

Downloads and installs the EternalBlue (MS17-010) patch. Requires
`Data/patchURLs.json` (bundled with the module). No prompts.

```powershell
Install-EternalBluePatch
```

### `Install-Splunk`

Downloads and runs the Splunk Universal Forwarder setup script. `-IP` is
mandatory; `-Version` is optional (defaults to empty).

```powershell
# Non-interactive (recommended)
Install-Splunk -Version 2022 -IP 10.0.0.5

# Interactive via the menu (menu option 16 prompts for IP and version)
Invoke-HardeningMenu -Force -Selection 16
```

### `Invoke-HardeningMenu`

The interactive menu. In non-interactive
mode use `-Force -Selection` to dispatch a single option directly.

```powershell
# Interactive
Invoke-HardeningMenu

# Non-interactive: run a specific option and exit
Invoke-HardeningMenu -Force -Selection 11       # Configure Firewall
Invoke-HardeningMenu -Force -Selection A        # Re-run setup
```

### `Invoke-WindowsHardening`

The main entry point. See [Parameters and Aliases](#parameters-and-aliases).

```powershell
# Interactive menu
Invoke-WindowsHardening

# Non-interactive quick-harden
Invoke-WindowsHardening -QuickHarden -SkipPasswordChange
Invoke-WindowsHardening -QuickHarden -FirewallPorts "80, 443" -SaltPhrase "a long passphrase"

# Menu over a WinRM session: the menu's firewall/network options keep WinRM open
Invoke-WindowsHardening -PreserveManagementPort
```

WinRM is disabled by default (by `Remove-RemoteManagement`); pass
`-PreserveManagementPort` to keep it. `-FirewallPorts`, `-PreserveManagementPort`,
`-SplunkIP`, and `-SaltPhrase` apply to both quick-harden and the menu.

### `Protect-Mimikatz` (alias `Patch-Mimikatz`)

Disables WDigest credential storage (`UseLogonCredential = 0`) to block
Mimikatz plaintext extraction. No prompts. A restart is recommended afterward.

```powershell
Protect-Mimikatz
# or the alias
Patch-Mimikatz
```

### `Remove-AdminUsers`

Removes users from the administrative groups (`Domain Admins`, `Enterprise
Admins`, `Administrators` on a DC; `Administrators` on a local machine),
preserving the specified exclusions. No prompts.

```powershell
Remove-AdminUsers
```

### `Remove-RDPUsers`

Removes all users from `Remote Desktop Users` except the module's exclusion
list (`ccdcuser1`, `ccdcuser2`). No prompts.

```powershell
Remove-RDPUsers
```

### `Restore-WindowsState` (experimental)

Restores a machine from a backup produced by `Backup-WindowsState`.
`-BackupPath` is **mandatory** and must point to the timestamped backup
subfolder. SHA256 checksums are verified before any restore; restore is aborted
on mismatch. Domain controllers are **not** demoted. Irreversible items (prior
passwords, AD objects) are logged to `MANUAL-RESET-REQUIRED.txt`.

```powershell
# Interactive not applicable — this is always parameter-driven
Restore-WindowsState -BackupPath "C:\Windows\System32\wbem\.hb\2026-08-26_120000"
```

### `Set-FirewallConfiguration` (alias `Configure-Firewall`)

Consolidated firewall configuration. It always creates a high-priority
`Deny All Inbound` rule, then allows specified ports. Domain-vs-local branching
is automatic based on detection.

```powershell
# Interactive (prompts for ports, confirmation)
Set-FirewallConfiguration

# Non-interactive: allow explicit ports (no prompts)
Set-FirewallConfiguration -FirewallPorts 80,443

# Keep WinRM (5985/5986) open so applying over WinRM does not lock you out
Set-FirewallConfiguration -FirewallPorts 80,443 -PreserveManagementPort
```

> `-FromQuickHarden` is used internally by `Start-QuickHarden`; you generally
> do not call it directly.

### `Set-ZuluPassword` (formerly `New-Zulu-Integration`)

Generates/rotates Zulu passwords. `-Initial` creates the competition users and
resets the Administrator password (menu option 6). Without prompts it uses the
provided file/seed/user parameters.

```powershell
# Interactive (prompts for users, seed, etc.)
Set-ZuluPassword

# Non-interactive: set up competition users and rotate passwords
Set-ZuluPassword -Initial -User ccdcuser1 -SaltPhrase "a long passphrase"

# Generate-only from a users file (no password change)
Set-ZuluPassword -GenerateOnly -UsersFile "users.csv"

# Write zulu.log / users_zulu.csv somewhere other than the log directory
Set-ZuluPassword -OutputDirectory "C:\zulu"
```

Parameter notes: `-SaltPhrase` (aliases `-s`, `-Seed`) sets the salt phrase;
`Invoke-WindowsHardening -SaltPhrase` passes it here for quick-harden and the
menu's password options. `-U`/`-u` both mean `-UsersFile` (PowerShell aliases
ignore case); spell out `-User` for a single user.

### `Start-QuickHarden`

Runs the quick-hardening sequence: services (SMB + unnecessary services) →
users/passwords/credentials → firewall + remote management → Splunk →
machine-wide (LocalMachine) execution policy set to Restricted. New sessions
need `-ExecutionPolicy Bypass` to load the module afterwards.

```powershell
# Interactive (prompts for the Splunk IP)
Start-QuickHarden

# Non-interactive
Start-QuickHarden -SkipPasswordChange -SkipRDP -SplunkIP 10.0.0.5 -FirewallPorts 80,443 -PreserveManagementPort
```

### `Update-SMB` (alias `Upgrade-SMB`)

Enables SMBv2/v3 and disables SMBv1 (where supported by the edition). No
prompts.

```powershell
Update-SMB
# or the alias
Upgrade-SMB
```

---

## Parameters and Aliases

Commonly used parameters and their short aliases:

| Parameter | Alias | Applies to |
|---|---|---|
| `-QuickHarden` | `-q` | `Invoke-WindowsHardening` |
| `-SkipPasswordChange` | `-sp` | `Invoke-WindowsHardening`, `Start-QuickHarden` |
| `-SkipRDP` | `-srdp` | `Invoke-WindowsHardening`, `Start-QuickHarden` |
| `-FirewallPorts` | `-f` | `Invoke-WindowsHardening`, `Set-FirewallConfiguration` |
| `-SaltPhrase` | `-s` | `Invoke-WindowsHardening`, `Start-QuickHarden`, `Invoke-UserHardening` |
| `-LogPath` | — | `Invoke-WindowsHardening` (default `C:\Windows\Logs\Hardening`) |
| `-PreserveManagementPort` | — | `Invoke-WindowsHardening`, `Start-QuickHarden`, `Set-FirewallConfiguration` |

### `Invoke-WindowsHardening` parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-QuickHarden` / `-q` | switch | `$false` | Run quick-hardening and exit |
| `-SkipPasswordChange` / `-sp` | switch | `$false` | Skip password change during QuickHarden |
| `-SkipRDP` / `-srdp` | switch | `$false` | Skip RDP-user removal during QuickHarden |
| `-FirewallPorts` / `-f` | string[] | — | Ports to allow; supports comma-separated (`"80, 443"`) |
| `-SaltPhrase` / `-s` | string | — | Salt phrase for Zulu passwords (else Zulu prompts) |
| `-LogPath` | string | `C:\Windows\Logs\Hardening` | Log output directory |
| `-PreserveManagementPort` | switch | `$false` | Keep WinRM reachable (firewall rules for TCP 5985/5986, service not disabled) |
| `-SplunkIP` | string | — | Splunk server IP for quick-harden and the menu (else prompts) |
| `-SkipSplunk` | switch | `$false` | Skip the Splunk step during QuickHarden |

### `Add-RDPUsers` parameters

| Parameter | Type | Description |
|---|---|---|
| `-Users` | string[] | Usernames to add |
| `-Force` | switch | Skip prompts (with no `-Users`, becomes a no-op) |

### `Backup-WindowsState` parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-BackupPath` | string | `C:\Windows\System32\wbem\.hb\` | Root backup directory (timestamped subfolder created) |

### `Install-Splunk` parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-IP` | string | Yes | Splunk server IP |
| `-Version` | string | No | OS version tag (`7`, `8`, `10`, `11`, `2012`, `2016`, ...) |

### `Invoke-HardeningMenu` parameters

| Parameter | Type | Description |
|---|---|---|
| `-Force` | switch | Dispatch a single selection and exit (no menu loop) |
| `-Selection` | string | Menu option when `-Force` (`0`, `A`, `1`–`17`) |

### `Restore-WindowsState` parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-BackupPath` | string | Yes | Timestamped backup subfolder to restore |

### `Set-FirewallConfiguration` parameters

| Parameter | Type | Description |
|---|---|---|
| `-FirewallPorts` | int[] | Ports to allow |
| `-FromQuickHarden` | switch | Internal — called by `Start-QuickHarden` |
| `-PreserveManagementPort` | switch | Keep Allow rules for WinRM (TCP 5985/5986) |

> There is **no** `-Force` parameter on `Set-FirewallConfiguration`. Prompting is
> suppressed by providing `-FirewallPorts`.

### `Start-QuickHarden` parameters

| Parameter | Alias | Description |
|---|---|---|
| `-SkipPasswordChange` | `-sp` | Skip password change / user creation |
| `-SkipRDP` | `-srdp` | Skip RDP-user removal |
| `-SplunkIP` | — | Splunk server IP (else prompts) |
| `-FirewallPorts` | — | Ports to allow (default: AD ports on a DC, Deny All only on local) |
| `-PreserveManagementPort` | — | Keep WinRM reachable |
| `-SaltPhrase` | — | Salt phrase for Zulu (else prompts) |
| `-SkipSplunk` | — | Skip the Splunk step |

---

## Backup and Restore

> **Experimental** (`Dev/`). Registry hive `.reg` files cannot be re-imported on
> a live system, so they are kept for offline recovery only.

`Backup-WindowsState` and `Restore-WindowsState` capture and restore the state
that hardening touches.

### Backup path

- Default: `C:\Windows\System32\wbem\.hb\` (dot-hidden, blends with the WMI
  repository).
- Override with `-BackupPath` on both functions.
- Each backup creates a timestamped subfolder:
  `<BackupPath>\<YYYY-MM-DD_HHmmss>\`.

### What is captured

1. Registry hives (`HKLM\SOFTWARE`, `HKLM\SYSTEM`, `HKU\.DEFAULT`) as `.reg`,
   plus security-relevant values as JSON.
2. Service startup types, accounts, and details.
3. Firewall profiles, rules, and a native configuration export.
4. Local users, groups, and memberships.
5. Audit policy (`auditpol`).
6. SMB server configuration.
7. WDigest `UseLogonCredential` value.
8. Execution policy.
9. LSA settings.
10. `checksums.txt` — SHA256 hash of every saved file.

### Restore

```powershell
# Non-interactive (there is no interactive path for restore)
$result = Restore-WindowsState -BackupPath "C:\Windows\System32\wbem\.hb\2026-08-26_120000"
$result.Success            # $true on clean restore
$result.RestoredCategories # categories restored (9 max)
$result.Errors             # empty on success, else per-category messages
$result.IsDomainController # $true when the target is a DC (never demoted)
```

> SHA256 checksum verification runs internally — before any restore (aborting on
> mismatch) and after restore (re-export versus original, logged) — but is not
> exposed as a return property.

- Restore runs in reverse order of capture (registry last, overwriting the
  WDigest/LSA values it restored earlier).
- SHA256 checksums are verified **before** any mutation; a mismatch logs an
  error and **aborts** — a corrupt backup is never applied.
- After restore, re-exports key state and compares checksums to the original
  backup. Restore is only declared successful when checksums match.
- Domain controllers remain promoted — restore does **not** demote them.
- Irreversible items (prior passwords, AD objects created by hardening) are
  written to `MANUAL-RESET-REQUIRED.txt` rather than restored.

```powershell
# Typical full cycle
$backup = Backup-WindowsState
Invoke-WindowsHardening -QuickHarden
Restore-WindowsState -BackupPath $backup.Path
```

---

## PS 5.1 Compatibility

- The manifest pins `PowerShellVersion = '5.1'`.
- Target machines run stock **Windows PowerShell 5.1**; the module does **not**
  require PowerShell 7 / Core.
- Module source is written to parse as PS 5.1 — no ternary (`? :`), no `??`,
  no `-Parallel`, no pipeline chain operators, no PS7-only cmdlets.
- Keep `.ps1`/`.psm1`/`.psd1` files **ASCII-only**. PS 5.1 reads BOM-less files
  as Windows-1252, where an em dash (`—`) decodes to a closing quote and breaks
  parsing, so the whole module fails to import.
- OS detection (`Get-OperatingSystemInfo`) covers Windows 10, Windows 11, and
  Windows Server 2016/2019/2022/2025, with edition-specific service lists,
  registry paths, and feature names guarded accordingly.

---

## Troubleshooting

**`Import-Module` fails with a parse error.**
Confirm you point at the `WindowsHardening` folder (not a single file) and that
you are not mixing in PS7-only syntax. Run:
```powershell
Import-Module ./WindowsHardening -Force -Verbose
```

**`Get-Command -Module WindowsHardening` is empty after import.**
The manifest exports an explicit function list. Re-import with `-Force` and
verify the path resolves to the folder containing `WindowsHardening.psd1` /
`.psm1`.

**`Disable-UnusedNetworkProtocols` / network steps skip adapters.**
These functions rely on adapter discovery. On Server Core or headless installs
network adapter modules may be reduced; check the log for `WARNING` lines about
adapters that could not be processed.

**`Install-EternalBluePatch` reports "patchURLs.json not found".**
It ships in the module's `Data/` folder; setup re-downloads it if it was
deleted. Without internet, copy `patchURLs.json` back into `Data/` and retry.

**`Install-Splunk` download fails over TLS.**
The function forces TLS 1.2 before downloading. Check the log for the underlying
`WebException` and confirm the machine can reach `raw.githubusercontent.com`
(proxy, firewall, or no outbound internet are the usual causes).

**`Protect-Mimikatz` (WDigest) change does not "stick".**
A system restart is required for `UseLogonCredential = 0` to fully take effect.
Reboot, then re-verify the `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
value.

**`Set-FirewallConfiguration` locks you out of remote management.**
If you apply hardening over WinRM, always pass `-PreserveManagementPort` so
Allow rules for WinRM (TCP 5985/5986) are kept. If you are already locked out,
use console access and run `Set-FirewallConfiguration -PreserveManagementPort`.

**`Restore-WindowsState` aborts with a checksum error.**
The backup `checksums.txt` does not match the current backup files (corruption,
partial copy, or edit). Do not force a restore; obtain an intact backup. The
restore intentionally refuses to apply a corrupt backup.

**Restore leaves `MANUAL-RESET-REQUIRED.txt` behind.**
This is expected. It lists irreversible items (e.g. prior passwords, AD objects
like `ccdcuser3`) that cannot be restored programmatically. Review and address
them manually for full reset.

**Changing the Administrator/domain password does not appear to work on a DC.**
DC password resets go through the AD path (`Set-UserPassword`). Check what the
module detected with `(Get-HardeningContext).OS.IsDomainController`. Detection
checks for the NTDS service, so a domain-joined member server is treated as a
local machine by design.

**A service disable is not reflected after re-run.**
Functions are safe to re-run. If a setting reverts (e.g. a service that
self-recovers), another policy may be re-applying it — check the event log and
the function's log output.

---

## Security Notes

- **WinRM / firewall.** Without `-PreserveManagementPort`, hardening disables
  WinRM, and RDP too unless `-SkipRDP` is given — expect console-only access
  afterwards.
