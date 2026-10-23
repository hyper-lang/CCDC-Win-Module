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
- [Domain Hardening](#domain-hardening)
- [Functions](#functions)
- [Parameters and Aliases](#parameters-and-aliases)
- [Backup and Restore](#backup-and-restore)
- [PS 5.1 Compatibility](#ps-51-compatibility)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Installation

### One-liner (download from GitHub and import)

Run in an elevated Windows PowerShell 5.1 session:

```powershell
irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1 | iex
```

`loader.ps1` downloads this repository's archive (it is small: the module and its
docs), keeps only the `WindowsHardening` folder in `%TEMP%\CCDC-Win-Module`, allows
unsigned scripts for the current session only (`-Scope Process`), and imports the
module. It doesn't use the GitHub API, so there's no rate limit. Nothing is
installed; open a new session and run it again to reload.

To pin a tag or commit, or test a branch:

```powershell
$loader = [scriptblock]::Create((irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1))
& $loader -Ref v1.0.0
& $loader -Ref my-branch
```

| Parameter | Default | Meaning |
|---|---|---|
| `-Repo` | `hyper-lang/CCDC-Win-Module` | The module's own repository |
| `-Path` | `WindowsHardening` | Module folder in that repository |
| `-Ref` | `main` | Branch, tag or commit |
| `-Destination` | `%TEMP%\CCDC-Win-Module` | Where the module goes (replaced on every run) |

> **Competitions:** CCDC requires team-written tools to be frozen at the version
> you declare. Tag that version (e.g. `v1.0.0`), declare the tag, and load it with
> `-Ref v1.0.0` (or set that as the `-Ref` default in the loader).

### Including the module in another repository

Other repositories, such as `BYU-CCDC/public-ccdc-resources`, can include this
repository as a git submodule, e.g. at `windows/hardening/CCDC-Win-Module`:

```bash
git submodule add https://github.com/hyper-lang/CCDC-Win-Module.git windows/hardening/CCDC-Win-Module
git commit -m "Add WindowsHardening module as a submodule"
```

A submodule is a pointer to one commit of this repository. To move it to the
latest `main`:

```bash
git submodule update --remote windows/hardening/CCDC-Win-Module
git commit -am "Update WindowsHardening submodule"
```

GitHub leaves submodules out of archive downloads and raw file links, so always
load the module from **this** repository's loader URL (above), not through the
other repository. Anyone cloning the other repository needs
`git clone --recurse-submodules`, or `git submodule update --init` afterwards, to
get the files.

### From a local copy

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
│   ├── Invoke-WindowsHardening.ps1, Invoke-HardeningMenu.ps1
│   ├── GPO/         Domain GPO import/link operations and role firewall policies
│   ├── Users/       Invoke-UserHardening, Set-AdministratorPassword, Create-CCDCUsers,
│   │                Set-ZuluPassword, Set-UserPassword, New-ADUserAccount, Remove-AdminUsers,
│   │                Remove-RDPUsers, Add-RDPUsers, Protect-Mimikatz
│   ├── Network/     Invoke-NetworkHardening, Set-FirewallConfiguration, Add-FirewallPort,
│   │                Get-FirewallPortOptions, Remove-RemoteManagement
│   ├── Services/    Invoke-ServiceHardening, Mitigate-EternalBlue, Disable-UnusedNetworkProtocols,
│   │                Set-RestrictedExecutionPolicy
│   ├── TH-IR/       Install-Splunk, Enable-AdvancedAuditing
│   ├── Patching/    Install-EternalBluePatch
│   ├── Messages/    Write-Status, Show-OperationSummary, Start-HardeningLog, Write-Banner,
│   │                Read-Choice, Read-YesNo, Read-HostAddress, Read-SecretInput
│   ├── Helpers/     One file per function, named after it: Initialize-System,
│   │                Initialize-Context, Get-HardeningContext, Test-Prerequisites,
│   │                Test-IsAdministrator, Test-IsDomainController, Test-HostAddress,
│   │                Get-OperatingSystemInfo, Invoke-HardeningOperation, ConvertTo-PortList,
│   │                Set-RegistryValue, Get-FileFromUrl, Show-Users, New-Password,
│   │                ConvertTo-WordIndex
│   └── Inject/      Reserved for inject-specific functions (empty for now)
├── Data/            ports.json, patchURLs.json, wordlist.txt
└── Dev/             Experimental: Backup-WindowsState, Restore-WindowsState + helpers
```

Data files are read from `Data/`, so the module works from any directory and
without internet access; setup downloads a file from GitHub only if it is
missing. Output goes to the log directory (`-LogPath`, default
`C:\Windows\Logs\Hardening`): the run log, a firewall backup per run (`fwback_<timestamp>.wfw`),
and Zulu's `zulu.log` / `users_zulu.csv`. Errors from a `Invoke-WindowsHardening`
run are also appended to `Desktop\hard.txt`.

OS and AD status (version, domain controller or not, domain membership) is
detected once, when the module is imported, and every function reads that cached
result. The rest of setup (`Initialize-System`: log file, data-file check) runs
automatically the first time a hardening step runs in a session, so functions can
be called on their own; run `Initialize-System -Force` to start over with a new
log file. `Get-HardeningContext` shows what the module detected.

---

## Quick Start

There are two entry points:

- **`Invoke-WindowsHardening`** runs the full sequence in order, including a WinRM choice
  before firewall configuration and an RDP choice after SMB hardening, then prints a summary.
- **`Invoke-HardeningMenu`** lets you pick individual sections or steps.

### Domain Hardening

`Invoke-DomainHardening` runs on a domain controller. It imports the `ActiveDirectory`
and `GroupPolicy` modules, downloads `gpos.zip` from the BYU-CCDC public resources
repository (or accepts a local archive with `-GpoZipPath`), imports the selected backups,
and links the policies. Existing same-name GPOs are updated from the backups.

The sequence changes the Administrator password, cleans the domain admin groups, rotates
Zulu passwords, and links `Domain Allow AD + Core + Default Block` to the domain root for
every computer, domain controllers included: all firewall profiles on, default inbound and
outbound blocked, local rules ignored, plus an added outbound NTP (UDP 123) rule. `DC Allow AD`
is linked to the Domain Controllers OU and layers the DC inbound rules on top, with added DFS
Replication rules (`dfsrs.exe` RPC in and TCP out) for SYSVOL, and outbound RPC (TCP 135 and
49152-65535) limited to the domain controllers' own addresses, read from AD on each run. It links `Domain Splomk` outbound access for `Domain Computers` and
`Domain Controllers`. It then links the update interval and `Domain Good-GPO` at the
root. These baseline links are **enforced**, so a GPO linked on an OU cannot override
them (for example by turning the firewall off) and Block Inheritance on an OU cannot
drop them. Role policies (database, web, mail, WinRM, SSH, RDP, FTP, SMB) are linked at
the root, filtered to the selected computer accounts, and not enforced. An OU with Block
Inheritance therefore drops them, but its computers keep the enforced baseline. Optional named port exceptions are applied through
targeted domain GPOs. Finally it runs `gpupdate /force`, configures Splunk if enabled,
and creates CCDC users.
WinRM is left running by this sequence.

By default, the run prompts for which Windows Server computers need each role, then for the Splunk indexer address. Splunk outbound
TCP 9997 is linked for all domain computers and domain controllers.
Domain controllers are included in those lists. Select multiple entries by entering
their numbers separated by commas (for example `1,3`), or pass arrays through
`-RoleServers`, such as `@{ Database = @('DB01','DB02') }`. Use `-SplunkIP` to supply
the indexer address. `-NoPrompt` skips role selection, so combine it with `-SkipSplunk`
or `-SplunkIP`.

The service roles create or update their own GPO with a direct computer-account filter.
The services themselves are left as they are:

| Role | GPO | Inbound allow | Default remote scope |
|---|---|---|---|
| WinRM | `CCDC Preserve WinRM` | TCP 5985, 5986 (System) | Any (`-WinRMRemoteAddress`) |
| SSH | `CCDC SSH Access` | TCP 22 | Any |
| RDP | `CCDC RDP Access` | TCP and UDP 3389 | Any |
| FTP | `CCDC FTP Access` | TCP 21; passive data TCP 1024-65535 and active data out from TCP 20, both limited to the IIS `ftpsvc` service | Any |
| SMB | `CCDC SMB Access` | TCP 445 (System) | Any |

Override a scope with `-RoleRemoteAddress`, for example `@{ RDP = 'LocalSubnet' }`, or
link a role on its own with `Link-ServerServiceGpo -Role SSH -ComputerName FILE01`. The
FTP data rules match only IIS FTP. For another FTP server, add its passive range with
`Add-DomainFirewallPortRule -Port 21, '50000-50100'`. Windows' stateful FTP setting is not a substitute: it does
not open passive ports, and the GPO version of the setting was not honored in testing.

```powershell
Invoke-DomainHardening -SaltPhrase 'a long passphrase' -SkipSplunk

Invoke-DomainHardening -NoPrompt -SaltPhrase 'a long passphrase' `
    -RoleServers @{ Database = @('DB01','DB02'); Web = @('WEB01'); SSH = @('WEB01'); RDP = @('JUMP01') } `
    -RoleRemoteAddress @{ RDP = 'LocalSubnet' } -SplunkIP '10.0.0.20'
```

The supplied domain firewall policy disables local firewall policy merging. A local
firewall allow rule may therefore be ignored on computers receiving that GPO. Add
exceptions with the functions below; each rule gets a separate domain GPO filtered to
the specified computers. You can also pass the add/remove requests into
`Invoke-DomainHardening` so the changes are followed by its `gpupdate /force` step.

```powershell
# Add inbound TCP 5432 only for DB01 and DB02
Add-DomainFirewallPortRule -Name 'Postgres' -ComputerName DB01,DB02 -Port 5432

# Ports and ranges can be mixed; each range is stored as one rule entry
Add-DomainFirewallPortRule -Name 'FileZilla' -ComputerName FTP01 -Port 21, '50000-50100'

# Add outbound TCP 9997 only for APP01, restricted to a specific indexer
Add-DomainFirewallPortRule -Name 'SplunkIndexer' -ComputerName APP01 -Port 9997 `
    -Direction Outbound -RemoteAddress 10.0.0.20

# Remove a previously created rule and its dedicated GPO
Remove-DomainFirewallPortRule -Name 'Postgres'

# The same operations can be queued as part of the full domain workflow
Invoke-DomainHardening -SkipPasswordChange -SkipSplunk `
    -FirewallPortRulesToAdd @(@{ Name='Postgres'; ComputerName=@('DB01','DB02'); Port=5432 }) `
    -FirewallPortRulesToRemove 'OldPort'
```

Outbound RPC to the domain controllers is allowed only from the DCs themselves. A member
cannot open RPC sessions to a DC, which blocks DCSync and WMI/DCOM from a compromised
member. Members that need it get a targeted exception. Examples: a certificate authority or
Exchange server, or a server about to be promoted to a DC (promotion fails with "Access
is denied" without it).

```powershell
$dcIPs = Get-ADDomainController -Filter * | ForEach-Object IPv4Address
Add-DomainFirewallPortRule -Name 'RPC-To-DCs' -ComputerName NEWDC01 -Port 135, '49152-65535' `
    -Direction Outbound -RemoteAddress $dcIPs
# gpupdate /force on NEWDC01, promote it, then:
Remove-DomainFirewallPortRule -Name 'RPC-To-DCs'
```

The DC list is a snapshot. After adding a DC or changing a DC's IP address, rerun
`Invoke-DomainHardening` on the PDC emulator to refresh it. AD replication itself does not
depend on this rule. Without the refresh, tools running on a DC (rerunning the hardening,
`repadmin`) cannot reach the new DC over RPC.

```powershell
Import-Module ./WindowsHardening -Force

# Full run (DC vs. member/workstation is auto-detected); asks whether WinRM/RDP are needed
Invoke-WindowsHardening -SaltPhrase "a long passphrase" -SkipSplunk

# Full run, no prompts at all
Invoke-WindowsHardening -SaltPhrase "a long passphrase" -SkipSplunk -NoPrompt

# Keep WinRM reachable (e.g. applied over a remote session)
Invoke-WindowsHardening -SaltPhrase "a long passphrase" -SkipSplunk -NoPrompt -PreserveManagementPort

# Skip password change and RDP-user reset
Invoke-WindowsHardening -SkipPasswordChange -SkipRDP -SkipSplunk

# Pick individual steps
Invoke-HardeningMenu
```

`Invoke-WindowsHardening` starts by prompting to change the Administrator password,
then prompts for the Zulu salt phrase (`-SaltPhrase`) and Splunk server IP
(`-SplunkIP`, or `-SkipSplunk`) as needed. Before firewall configuration, it asks whether
WinRM is needed; answer Yes to keep it enabled and add TCP 5985/5986 allow rules, or No to
disable it without adding those standard exceptions. The firewall keeps default ports (plus `-FirewallPorts` /
`-AdditionalPorts`) and asks for extra ones. After SMB hardening, it asks whether RDP
is needed; answer Yes to keep it enabled or No to disable it. `-NoPrompt` skips the WinRM,
RDP, and extra-port questions. WinRM is disabled unless `-SkipWinRM` or
`-PreserveManagementPort` is given; RDP is disabled unless `-SkipRDP` is given. Required password or Splunk
prompts still occur unless their values or skip switches are provided.

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
adapters. No prompts.

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
`Data/patchURLs.json` (bundled with the module). This is a standalone operation and
is not part of `Invoke-WindowsHardening`; installing it may require a restart to finish.
No prompts.

```powershell
Install-EternalBluePatch
```

### `Enable-AdvancedAuditing`

Enables auditing for logon, account-management, object-access, policy-change,
privilege-use, and process events, adds a file-system audit rule on each fixed
drive, and turns on firewall logging (allowed + blocked). Always non-interactive.

```powershell
Enable-AdvancedAuditing

# Or via the menu (option 15)
Invoke-HardeningMenu -Force -Selection 15
```

### `Install-Splunk`

Downloads and runs the CCDC `splunk.ps1` to install the Splunk Universal
Forwarder, forwarding to `<IP>:9997`. `-IP` is mandatory (just the address;
`splunk.ps1` adds the port). `splunk.ps1` detects the Windows version itself;
`-Version` overrides it. `splunk.ps1` prompts for the Splunk admin password.

```powershell
Install-Splunk -IP 10.0.0.5

# Override the detected version (10, 2019, 2012R2, or "Windows Server 2019")
Install-Splunk -IP 10.0.0.5 -Version 2019

# Via the menu (option 16 prompts for the IP)
Invoke-HardeningMenu -Force -Selection 16
```

### `Invoke-HardeningMenu`

The interactive menu. The main screen lists the sections with their option
numbers; a section letter opens that section's options:

| Letter | Section | Options |
|---|---|---|
| — | Harden Everything (`Invoke-WindowsHardening`, new log file) | 1 |
| `U` | Users & Credentials | 2 (run all), 5-10, 20 |
| `N` | Network & Remote Access | 3 (run all), 11, 12, 19 |
| `S` | Services | 4 (run all), 13, 14, 18 |
| `L` | Logging | 15, 16 |
| `P` | Patching | 17 |
| — | Re-run setup / execution summary | A / 0 |

Option numbers can be typed from any screen, several at once (`9,10,13` or
`13-15`), and run in the order typed. `Q` goes back from a section and quits from
the main screen. Requires an elevated session. With `-Force -Selection`, runs one
option and returns.

```powershell
# Interactive
Invoke-HardeningMenu

# Keep WinRM open when the firewall/network options run over a WinRM session
Invoke-HardeningMenu -PreserveManagementPort

# Non-interactive: run a specific option and exit
Invoke-HardeningMenu -Force -Selection 11       # Configure Firewall
Invoke-HardeningMenu -Force -Selection A        # Re-run setup
```

### `Invoke-WindowsHardening`

Runs the full hardening sequence: Administrator password change → admin cleanup →
existing-user password rotation → firewall → ZeroLogon mitigation → SMB hardening →
RDP choice and cleanup → credential protection → remote-management teardown → protocol
hardening → Splunk → CCDC account creation → restricted execution policy. The section
orchestrators remain available for independent user, network, and service runs. Each
operation is counted so one failure is reported without stopping the rest. See
[Parameters and Aliases](#parameters-and-aliases).

```powershell
Invoke-WindowsHardening -SaltPhrase "a long passphrase" -SkipSplunk
Invoke-WindowsHardening -FirewallPorts "80, 443" -SaltPhrase "a long passphrase" -SplunkIP 10.0.0.5
```

Without `-FirewallPorts`, a domain controller gets the common AD ports and any
other machine gets Deny All Inbound only; either way the run then asks for extra
ports to allow, unless `-NoPrompt` is given. The WinRM prompt asks whether WinRM is needed:
Yes keeps it enabled and allows TCP 5985/5986, No disables it without adding those standard exceptions.
The RDP prompt asks whether RDP is needed: Yes keeps RDP enabled, No disables it.
`-SkipWinRM` keeps WinRM enabled and preserves its ports without asking; `-DisableWinRM`
disables it without asking. `-PreserveManagementPort` has the same keep effect. The
execution policy is set to Restricted machine-wide, so new sessions need
`-ExecutionPolicy Bypass` to load the module afterwards.

### `Invoke-DomainHardening`

Runs on a domain controller. Downloads or accepts the GPO backup ZIP, imports the
ActiveDirectory and GroupPolicy modules, imports the competition GPOs, then links the
DC policy, domain firewall policy, domain Splunk outbound policy, update interval,
domain baseline (all enforced), and selected role firewall policies. It can also add or remove named
per-computer firewall GPO exceptions using `-FirewallPortRulesToAdd` and
`-FirewallPortRulesToRemove`. It runs `gpupdate /force` before the final Splunk and
CCDC account steps. See [Domain Hardening](#domain-hardening) for scopes and examples.

### `Protect-Mimikatz`

Disables WDigest credential storage (`UseLogonCredential = 0`) to block
Mimikatz plaintext extraction. No prompts. A restart is recommended afterward.

```powershell
Protect-Mimikatz
```

### `Remove-AdminUsers`

Removes users from the administrative groups (`Domain Admins`, `Enterprise
Admins`, `Administrators` on a DC; `Administrators` on a local machine),
preserving `Administrator` plus `ccdcuser3` on a DC or `ccdcuser1` on a local
machine. No prompts.

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

### `Set-FirewallConfiguration`

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

# Keep the defaults (AD ports on a DC) and add a database + web port on top
Set-FirewallConfiguration -NonInteractive -AdditionalPorts 1433,8080

# Keep the defaults, then pick extra ports from a list (or type any port)
Set-FirewallConfiguration -Prompt
```

Re-running does not duplicate rules: an existing `Allow <Protocol> <Port>` rule is
re-enabled instead. Any enabled inbound Block rule covering an allowed port is
reported, since Block rules override Allow rules.

### `Add-FirewallPort`

Opens extra inbound ports on an already-hardened firewall without resetting it
(menu option 19). Existing rules for the port are reused, not duplicated.

```powershell
Add-FirewallPort -Ports 1433               # TCP (TCP + UDP on a DC)
Add-FirewallPort -Ports "161" -Protocol UDP
```

> `-NonInteractive` (never prompt; AD ports on a DC, Deny All only otherwise)
> is what `Invoke-WindowsHardening` uses.

### `Set-ZuluPassword`

Generates or rotates Zulu passwords for existing eligible users. The Administrator
password and competition accounts are handled separately by
`Set-AdministratorPassword` and `Create-CCDCUsers`.

Competition accounts created by `Create-CCDCUsers`:

| Machine | Admin account | Standard account |
|---|---|---|
| Domain controller | `ccdcuser3` (AD, Domain Admins) | `ccdcuser2` (AD) |
| Local machine | `ccdcuser1` (local Administrators) | `ccdcuser2` (local) |

```powershell
# Interactive (prompts for users, seed, etc.)
Set-ZuluPassword

# Change the built-in Administrator password
Set-AdministratorPassword

# Create competition accounts
Create-CCDCUsers -SaltPhrase "a long passphrase"

# Generate-only from a users file (no password change)
Set-ZuluPassword -GenerateOnly -UsersFile "users.csv"

# Write zulu.log / users_zulu.csv somewhere other than the log directory
Set-ZuluPassword -OutputDirectory "C:\zulu"
```

On Linux, `-GenerateOnly` writes the generated `users_zulu.csv` to the current
working directory by default. It contains `Username,Password` rows; pass
`-OutputDirectory` to choose another location. Both platforms mask the
interactive seed prompt. Generated passwords are intentionally plaintext in
this CSV and on the Windows generate-only console output.

`-GenerateOnly` does not run administrator pre-flight checks or require an
elevated PowerShell session.

Parameter notes: `-SaltPhrase` (aliases `-s`, `-Seed`) sets the salt phrase;
`Invoke-WindowsHardening -SaltPhrase` and `Invoke-HardeningMenu -SaltPhrase`
pass it here. `-U`/`-u` both mean `-UsersFile` (PowerShell aliases
ignore case); spell out `-User` for a single user.

### `Mitigate-EternalBlue`

Enables SMBv2/v3, disables SMBv1, and requires SMB server signing (where
supported by the edition). This mitigates EternalBlue by removing SMBv1. Its
operation name in progress output and the run summary is `Mitigate EternalBlue`.
No prompts.

```powershell
Mitigate-EternalBlue
```

---

## Parameters and Aliases

Commonly used parameters and their short aliases:

| Parameter | Alias | Applies to |
|---|---|---|
| `-SkipPasswordChange` | `-sp` | `Invoke-WindowsHardening` |
| `-SkipRDP` | `-srdp` | `Invoke-WindowsHardening` |
| `-SkipWinRM` | `-swrm` | `Invoke-WindowsHardening` |
| `-DisableWinRM` | `-dwrm` | `Invoke-WindowsHardening` |
| `-FirewallPorts` | `-f` | `Invoke-WindowsHardening`, `Set-FirewallConfiguration` |
| `-AdditionalPorts` | `-ap` | `Invoke-WindowsHardening` |
| `-SaltPhrase` | `-s` | `Invoke-WindowsHardening`, `Invoke-HardeningMenu`, `Invoke-UserHardening` |
| `-LogPath` | — | `Invoke-WindowsHardening` (default `C:\Windows\Logs\Hardening`) |
| `-PreserveManagementPort` | — | `Invoke-WindowsHardening`, `Invoke-HardeningMenu`, `Set-FirewallConfiguration` |

### `Invoke-WindowsHardening` parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SkipPasswordChange` / `-sp` | switch | `$false` | Skip Zulu account creation and password rotation |
| `-SkipRDP` / `-srdp` | switch | `$false` | Keep RDP enabled and skip the RDP group reset, without asking |
| `-DisableRDP` / `-drdp` | switch | `$false` | Disable RDP and reset the RDP group, without asking. With neither RDP switch, the run asks whether RDP is needed after SMB hardening |
| `-SkipWinRM` / `-swrm` | switch | `$false` | Keep WinRM enabled and allow TCP 5985/5986, without asking |
| `-DisableWinRM` / `-dwrm` | switch | `$false` | Disable WinRM without adding its standard firewall allow rules, without asking. With neither WinRM switch nor `-PreserveManagementPort`, the run asks before configuring the firewall |
| `-FirewallPorts` / `-f` | string[] | AD ports on a DC, none otherwise | Ports to allow; supports comma-separated (`"80, 443"`) |
| `-AdditionalPorts` / `-ap` | string[] | — | Extra ports allowed on top of `-FirewallPorts` or the defaults |
| `-NoPrompt` | switch | `$false` | Don't ask whether WinRM or RDP is needed (both are disabled unless their keep switch is given) or for extra firewall ports |
| `-SaltPhrase` / `-s` | string | — | Salt phrase for Zulu passwords (else Zulu prompts) |
| `-LogPath` | string | `C:\Windows\Logs\Hardening` | Log output directory |
| `-PreserveManagementPort` | switch | `$false` | Keep WinRM reachable (firewall rules for TCP 5985/5986, service not disabled); same as `-SkipWinRM` |
| `-SplunkIP` | string | — | Splunk server IP (else prompts) |
| `-SkipSplunk` | switch | `$false` | Skip the Splunk step (no prompt) |

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
| `-Version` | string | No | Override the auto-detected Windows version (`10`, `2019`, `2012R2`, or `Windows Server 2019`) |

### `Invoke-HardeningMenu` parameters

| Parameter | Type | Description |
|---|---|---|
| `-Force` | switch | Dispatch a single selection and exit (no menu loop) |
| `-Selection` | string | Menu option when `-Force` (`0`, `A`, `1`–`19`) |
| `-FirewallPorts` | int[] | Ports for the firewall options |
| `-AdditionalPorts` | int[] | Extra ports for the firewall options (and the default for option 19) |
| `-PreserveManagementPort` | switch | Keep WinRM reachable in the firewall/network options |
| `-SplunkIP` | string | Splunk server IP (else prompts) |
| `-SaltPhrase` | string | Salt phrase for the Zulu options (else prompts) |

### `Restore-WindowsState` parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-BackupPath` | string | Yes | Timestamped backup subfolder to restore |

### `Set-FirewallConfiguration` parameters

| Parameter | Type | Description |
|---|---|---|
| `-FirewallPorts` | int[] | Ports to allow |
| `-AdditionalPorts` | int[] | Extra ports allowed on top of whichever set was chosen |
| `-Prompt` | switch | Keep the defaults (or `-FirewallPorts`), then ask for extra ports; works with `-NonInteractive` |
| `-NonInteractive` | switch | Never prompt (used by `Invoke-WindowsHardening`) |
| `-PreserveManagementPort` | switch | Keep Allow rules for WinRM (TCP 5985/5986) |

> There is **no** `-Force` parameter on `Set-FirewallConfiguration`. Prompting is
> suppressed by providing `-FirewallPorts`.

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
Invoke-WindowsHardening -SaltPhrase "a long passphrase" -SkipSplunk
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

- **WinRM / firewall.** The full run asks whether WinRM is needed and aligns the
  TCP 5985/5986 firewall rules with that choice. `-NoPrompt` disables WinRM unless
  `-SkipWinRM` or `-PreserveManagementPort` is given. RDP is disabled unless
  `-SkipRDP` is given. Plan access accordingly before applying hardening remotely.
