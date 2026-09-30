# Developing WindowsHardening

This guide is for people changing the module. It covers how the code is laid out, how
the module loads and initializes, how hardening steps and orchestrators fit together,
and the helper functions you should use instead of writing your own. For how to *run*
the module, see [README.md](README.md).

## Contents

- [Folder structure](#folder-structure)
- [How the module loads](#how-the-module-loads)
- [Shared state and the hardening context](#shared-state-and-the-hardening-context)
- [Initialization](#initialization)
- [Invoke-HardeningOperation: the step runner](#invoke-hardeningoperation-the-step-runner)
- [Orchestrators](#orchestrators)
- [The menu](#the-menu)
- [Output helpers](#output-helpers)
- [Prompt helpers](#prompt-helpers)
- [Other helpers](#other-helpers)
- [PowerShell pitfalls that have bitten this code](#powershell-pitfalls-that-have-bitten-this-code)
- [Testing](#testing)
- [Checklist: adding a new hardening step](#checklist-adding-a-new-hardening-step)

---

## Folder structure

```
CCDC-Win-Module/
├── loader.ps1                 One-liner bootstrap: download this repo's zip, import the module
├── README.md                  User documentation
├── DEVELOPING.md              This file
└── WindowsHardening/
    ├── WindowsHardening.psd1  Manifest: version, and the explicit FunctionsToExport list
    ├── WindowsHardening.psm1  Root module: shared state, dot-sources every .ps1, detects the OS
    ├── Data/                  ports.json, patchURLs.json, wordlist.txt (bundled; read at runtime)
    ├── Dev/                   Experimental: Backup-WindowsState, Restore-WindowsState + helpers
    └── Public/
        ├── Invoke-WindowsHardening.ps1   Top-level entry point: the full run
        ├── Invoke-HardeningMenu.ps1      Top-level entry point: pick steps from a menu
        ├── Users/       User & credential steps + Invoke-UserHardening (section orchestrator)
        ├── Network/     Firewall & remote access steps + Invoke-NetworkHardening
        ├── Services/    SMB, protocols, execution policy + Invoke-ServiceHardening
        ├── SIEM/        Install-Splunk, Enable-AdvancedAuditing
        ├── Patching/    Install-EternalBluePatch
        ├── Messages/    Output and prompts: Write-Status, Write-Banner, Read-Choice, Log.ps1, ...
        ├── Helpers/     Shared plumbing, one function per file, file named after the function
        └── Inject/      Reserved for competition inject tasks (empty)
```

Where to put new code:

| You are adding... | Put it in |
|---|---|
| A hardening step (changes the system) | The matching section folder (`Users/`, `Network/`, ...) |
| A new section | A new folder under `Public/` plus an `Invoke-<Section>Hardening` orchestrator |
| Something that prints or prompts | `Messages/` |
| Reusable plumbing with no hardening effect of its own | `Helpers/`, one function per file |
| Something not ready for competition use | `Dev/` |
| A one-off inject task | `Inject/` |

A file may hold more than one function when they belong together. For example,
`Network/Add-FirewallPort.ps1` also holds `Get-FirewallPortDescription` and
`Set-FirewallAllowRule`, which `Set-FirewallConfiguration` uses too, and
`Users/UserManagement.ps1` holds the account-creation functions.

---

## How the module loads

### From the web: `loader.ps1`

`irm .../loader.ps1 | iex` does the following:

1. Enables TLS 1.2, since Windows PowerShell 5.1 defaults to protocols GitHub rejects,
   and turns off the progress bar, which slows 5.1 downloads badly.
2. Sets the execution policy to `Bypass` for the Process scope only. The module is unsigned.
3. Downloads `https://github.com/<Repo>/archive/<Ref>.zip`, the archive of this
   repository, which is small. `-Repo` defaults to `hyper-lang/CCDC-Win-Module`.
4. Extracts it to a temporary folder. The archive holds one top folder named after the
   repo and ref (e.g. `CCDC-Win-Module-main`). It moves only `-Path` (default
   `WindowsHardening`) to `%TEMP%\CCDC-Win-Module`, which is replaced on every run, and
   deletes the rest. On Windows, it runs `Unblock-File` on the module's files.
5. Imports `WindowsHardening.psd1` with `-Global`.

Nothing is installed, and no GitHub API is involved, so there is no rate limit. `-Ref`
selects a branch, tag or commit, which makes it easy to test a branch on a VM, and to
pin the tag declared for a competition.

**Submodules:** other repositories (e.g. `BYU-CCDC/public-ccdc-resources`) include this
repository as a git submodule. GitHub leaves submodules out of archive downloads and raw
file links, so the loader always downloads from this repository. That's why the same
`loader.ps1` works however it was reached. Updating the submodule pointer in the other
repository is only for people browsing or cloning it; the loader doesn't depend on it.

### `Import-Module`: `WindowsHardening.psm1`

The root module runs top to bottom, once per import:

1. **Paths.** It sets `$script:DataPath` (the `Data/` folder next to the module) and
   `$script:DefaultLogPath` (`C:\Windows\Logs\Hardening`).
2. **Shared state.** It creates `$script:HardeningContext`, `$script:LogFile`,
   `$script:log` and `$script:OperationResults`. See the next section.
3. **Dot-sourcing.** It dot-sources every `Public/**/*.ps1`, sorted by full path, then
   every `Dev/*.ps1`. Functions defined this way live in module scope, so they can call
   each other in any order. **Top-level code in a file also runs at this point.** A few
   files use that to define module constants: `Log.ps1` defines
   `$script:TrackedOperations`, and `Initialize-Context.ps1` defines
   `$script:CcdcRepoUrl`, `$script:RequiredFiles` and `$script:FallbackPorts`. Keep
   top-level code to constants. Don't call functions there, because the file defining
   them may not have been sourced yet.
4. **OS detection.** It calls `Get-OperatingSystemInfo` once, which caches the result in
   `$script:HardeningContext.OS`. If detection throws, the module still imports, with a
   warning.

Logging and the data files are **not** set up at import. That happens on first use (see
[Initialization](#initialization)), so importing the module has no side effects on the
machine.

### Exports

The manifest's `FunctionsToExport` is an explicit list. Everything is dot-sourced, but
only listed functions are visible outside the module. That means:

- **A new public function must be added to `FunctionsToExport`**, or users can't call
  it. The module still imports without it, so nothing warns you.
- Internal helpers are simply left off the list: `Write-Log`,
  `Get-FirewallPortDescription`, `Set-FirewallAllowRule`. Module functions can still
  call them.
- Removing a function file without removing its manifest entry causes no error on
  import either. Check with the script in [Testing](#testing).

---

## Shared state and the hardening context

All shared state is module-scoped (`$script:`). Nothing uses globals except the
`$global:Error` bookkeeping described in the pitfalls section.

| Variable | Set by | Holds |
|---|---|---|
| `$script:HardeningContext.OS` | `Get-OperatingSystemInfo` at import | OS object (below); `$null` if detection failed |
| `$script:HardeningContext.LogPath` | `Start-HardeningLog` | Log directory; also where the `fwback_<timestamp>.wfw` firewall backups and Zulu output go |
| `$script:HardeningContext.CurrentUser` | `Initialize-System` | `DOMAIN\user` running the module |
| `$script:HardeningContext.Ports` | `Initialize-Context` | Parsed `ports.json`, or `$script:FallbackPorts` |
| `$script:HardeningContext.Initialized` | `Initialize-System` | Whether setup has run this session |
| `$script:DataPath` | `.psm1` | Path to `Data/` |
| `$script:LogFile` | `Start-HardeningLog` | Current log file; `$null` means logging is off (Write-Log does nothing) |
| `$script:log` | `Set-OperationStatus` | Map of operation name to status text, shown by `Show-OperationSummary` |
| `$script:OperationResults` | `Invoke-HardeningOperation` | `Total` / `Successful` / `Failed` / `Skipped` counters and `Warnings` |
| `$script:TrackedOperations` | `Log.ps1` | Operation names pre-filled as "Not executed" in the summary |
| `$script:NextStepLabel` | Orchestrators | One-shot step label like `Users 2/4` (see [Orchestrators](#orchestrators)) |

The OS object's properties are `Caption`, `Version`, `BuildNumber`, `OSVersion` (for
example `Windows Server 2022`), `OSFamily` (for example `Server2022` or `Client10`,
which is what `-OSCompatibility` matches against), `Edition`, `IsServer`, `IsServerCore`,
`ProductType`, `IsDomainController`, `IsDomainJoined`, `Domain` and `Workgroup`.

**Always read DC status from `$script:HardeningContext.OS.IsDomainController`** (or
`(Get-OperatingSystemInfo).IsDomainController`, which returns the cached object). Don't
call `Test-IsDomainController` directly; it's the raw probe that detection uses.

`Get-HardeningContext` returns a snapshot (a shallow copy) of the context. It's handy
for debugging from a session: `Get-HardeningContext | Format-List`.

---

## Initialization

`Initialize-System` is the module's single setup path. It is idempotent: after the first
run it returns immediately unless `-Force` is given.

```
Initialize-System [-Force] [-LogPath <dir>]
  1. Initialized = $true          (set first: see "recursion" below)
  2. OS = Get-OperatingSystemInfo (returns the cached object from import)
  3. CurrentUser                  set here so the log header can include it
  4. Start-HardeningLog           new Hardening_<timestamp>.log; resets counters and $script:log
  5. Reset-OperationStatus        pre-fills every $script:TrackedOperations name as "Not executed"
  6. Initialize-Context           an operation of its own, "Initialize Context":
                                    - downloads any missing Data/ file from $script:CcdcRepoUrl
                                    - loads ports.json (or the fallback table)
```

Who calls it:

- **`Invoke-HardeningOperation` calls it at the start of every step.** That is why any
  step works when called on its own in a fresh session.
- **`Invoke-WindowsHardening` calls `Initialize-System -Force -LogPath $LogPath`**, so
  every full run gets its own log file and fresh counters.
- **Menu option `A`** calls `Initialize-System -Force`.
- **Menu option 19 and `Show-Users`** call it directly, because they need `ports.json`
  (or the log) before any step runs.

Things to know:

- **Recursion.** `Initialize-Context` runs inside `Invoke-HardeningOperation`, which
  calls `Initialize-System`. The `Initialized` flag is set *before* that happens, so the
  inner call returns immediately. Don't move that line.
- **`-Force` does not re-detect the OS.** `Get-OperatingSystemInfo` returns the cached
  result. Re-import the module (`Import-Module ... -Force`) to re-detect.
- **"Initialize Context" counts as an operation**, so a clean full run reports one more
  operation than the number of hardening steps.
- **Output before initialization doesn't reach the new log.** `Write-Status` calls made
  before `Initialize-System` go to the screen only, or to the *previous* log file if one
  was open. This includes the parameter echo at the top of `Invoke-WindowsHardening`.

---

## Invoke-HardeningOperation: the step runner

Every function that changes the system wraps its body in `Invoke-HardeningOperation`:

```powershell
# Simplified from Users/Protect-Mimikatz.ps1
function Disable-WDigestCaching {
    [CmdletBinding()]
    param()

    $compatible = @("Client10", "Client11", "Server2016", "Server2019", "Server2022", "Server2025")

    Invoke-HardeningOperation -OperationName "Disable WDigest" -OSCompatibility $compatible `
        -ProgressMessage "Disabling WDigest credential storage" -ScriptBlock {
        Set-RegistryValue -Path "HKLM:\...\WDigest" -Name "UseLogonCredential" -Value 0 `
            -PropertyType DWord -CreatePathIfMissing
    }
}
```

What it does, in order:

1. Takes `$script:NextStepLabel` (if an orchestrator set one) and clears it.
2. Calls `Initialize-System`, which does nothing after the first time.
3. Increments `OperationResults.Total`.
4. If `-OSCompatibility` is given and `OS.OSFamily` isn't in the list, it logs a skip,
   increments `Skipped`, records "Skipped - OS incompatible" and returns without running
   the script block.
5. Prints the header (`[Users 1/4] Remove Admin Users` or `[EXECUTING] ...`) and runs the
   script block.
6. If the block finishes, it prints `<name> completed successfully`, increments
   `Successful`, and sets the status to "Executed successfully".
7. If the block throws a `System.OperationCanceledException`, it counts a **skip**, not
   a failure, and records "Skipped - <message>". Throw this when the user backs out,
   for example by pressing Q at a prompt:
   `throw [System.OperationCanceledException]::new("Cancelled by user")`.
8. If the block throws anything else, it prints the error, exception type and inner
   exception, increments `Failed`, and records "Failed with error: ...". **It does not
   rethrow.** That is what lets one failed step leave the rest of the run going.

Rules for the script block:

- **Throw to fail; throw `OperationCanceledException` to skip.** A step that hits a
  problem it can't work around should `throw`. A
  problem that is only worth mentioning should be a `Write-Status -Level Warning`; the
  step still counts as successful.
- **Non-terminating errors don't fail a step.** Most cmdlets report problems as
  non-terminating errors, which never reach the runner's `catch`. Add
  `-ErrorAction Stop` to any call whose failure should fail the step.
- **Scope.** The block runs in a child scope of the function that defined it, so it can
  *read* that function's parameters (`$Ports`, `$Protocol`, ...). An *assignment* such
  as `$Protocol = 'TCP'` creates a new local variable inside the block. That's fine for
  defaults, but the outer variable doesn't change.
- **`return` exits the block early** and still counts as a success.
- **The operation name is the status key.** For a step to show as "Not executed" in the
  summary when it doesn't run, add its `-OperationName` to `$script:TrackedOperations`
  in `Messages/Log.ps1`. Names must match exactly.
- A function can record extra status lines itself with
  `Set-OperationStatus "<key>" "<text>"`. `Set-ZuluPassword` does this for
  "Add Competition Users" and "Change Passwords".

Don't wrap orchestrators or the menu in `Invoke-HardeningOperation`. They aren't
operations; they call operations.

---

## Orchestrators

There are two levels:

```
Invoke-WindowsHardening                 full run; new log; pre-flight checks; final summary
├── Invoke-UserHardening                Users 1/4 .. 4/4
│   ├── Remove-AdminUsers
│   ├── Set-ZuluPassword -Initial       ("Zulu Passwords" operation)
│   ├── Remove-RDPUsers
│   └── Protect-Mimikatz
├── Invoke-ServiceHardening             Services 1/2 .. 2/2
│   ├── Update-SMB
│   └── Disable-UnusedNetworkProtocols
├── Invoke-NetworkHardening             Network 1/2 .. 2/2
│   ├── Set-FirewallConfiguration
│   └── Remove-RemoteManagement
├── Install-Splunk                      unless -SkipSplunk
└── Set-RestrictedExecutionPolicy       always last (see below)
```

### Section orchestrators (`Invoke-<Section>Hardening`)

They all follow one pattern:

```powershell
Write-Banner "Service Hardening"                      # Box banner: screen + log section marker

if (-not $SkipSMB) {
    $script:NextStepLabel = 'Services 1/2'            # consumed by the next Invoke-HardeningOperation
    Update-SMB
} else {
    Write-Host ""
    Write-Status -Level Skip -Tag 'Services 1/2' "SKIPPED - SMB hardening (-SkipSMB)" `
        -LogMessage "Invoke-ServiceHardening: SMB hardening skipped"
}
# ... next step ...

Write-Host ""
Write-Status -Tag Services "Done." -LogMessage "Invoke-ServiceHardening completed"
```

- Each step gets a `-Skip<Step>` switch, so callers can leave one out.
- **`$script:NextStepLabel` is one-shot.** It is read and cleared by the next
  `Invoke-HardeningOperation`, so set it right before the call. If the called function
  can return *before* reaching `Invoke-HardeningOperation` (for example by validating
  parameters first and throwing), the label stays set and ends up on whatever operation
  runs next.
- **Order matters, and each file's help text says why.** Admin removal comes before
  password rotation, and rotation comes early so stolen credentials stop working as soon
  as possible. The firewall closes before remote-management services are torn down.

### `Invoke-WindowsHardening`

1. Parses `-FirewallPorts` / `-AdditionalPorts` with `ConvertTo-PortList`, so bad input
   fails before anything changes.
2. Runs `Initialize-System -Force -LogPath $LogPath`, which starts a new log and resets
   the counters.
3. Shows the OS and AD status, then runs `Test-Prerequisites`, which throws if the
   session isn't elevated.
4. Runs the three section orchestrators, then Splunk, then the execution policy.
   `Invoke-NetworkHardening` always gets `-NonInteractive`, plus `-Prompt` unless
   `-NoPrompt` was given.
5. Shows the summary with `Show-OperationSummary`, appends this run's new
   `$global:Error` entries to `Desktop\hard.txt`, and prints the overall result.

`Set-RestrictedExecutionPolicy` sets the **LocalMachine** policy. The current session
keeps its Process-scope `Bypass`, so it runs last, and later sessions get `Restricted`.

**Prompts in a full run.** A full run prompts for what wasn't passed: the Zulu salt
(`-SaltPhrase`) and the Splunk IP (`-SplunkIP` / `-SkipSplunk`). Unless `-NoPrompt` is
given, it also asks up front whether to disable RDP (`-DisableRDP` / `-SkipRDP` answer in
advance) and, at the firewall step, for extra firewall ports. Over WinRM there is no
console, and `Read-Host` throws. Both questions catch that: RDP is disabled, and the
firewall continues with the default ports. Anything new that prompts needs a parameter
that bypasses it.

---

## The menu

`Invoke-HardeningMenu` is data-driven:

- **`$menuOptions`** lists every option: `Key`, `Label`, and `Section`, the letter of the
  sub-menu it appears in (`U`, `N`, `S`, `L`, `P`). Options without a section (1, A, 0) are on
  the main screen. Within a section, options appear in list order, so each section's
  "run all" orchestrator comes first. Keys never change (19 is in the Network section),
  so typed numbers, `-Selection` and the README stay valid.
- **`$menuSections`** maps each letter to its section name, in main-screen order. The
  main screen shows each section with its option numbers, e.g.
  `U) Users & Credentials (2, 5-10)`.
- **`Get-ScreenOptions [-Section <letter>]`** builds the `Read-Choice` options for a
  screen. It lists that screen's options and passes every other option as `Hidden`, so
  any option number, or a range like `13-15`, works from any screen.
- **`Invoke-MenuAction`** is a `switch` on the key; each case calls one function.
  Before the switch, it prints a header built from the option's `$menuOptions` label
  (`=== Menu 11: Configure Firewall ===`) and writes it to the log, so the log records
  which options ran. Don't add headers inside the cases.
- The loop uses `Read-Choice -Multiple`, so `9,10,13` or `13-15` run several options in
  the order typed. A section letter opens that sub-menu, where Q goes back; `u,14`
  opens Users, then runs 14 after whatever was picked there.
- `-Force -Selection <key>` runs exactly one option and returns, for scripting.
- Menu parameters (`-FirewallPorts`, `-SaltPhrase`, ...) are passed down to the options
  that take them.

Menu errors are reported as `Menu option <key> failed: <message>`, on screen and in
the log.

To add an option, add an entry to `$menuOptions` (with its `Section`) and a case to
`Invoke-MenuAction`. Then update the option range in the help text ("5-19") and in the
README's `Invoke-HardeningMenu` section. To add a section, add its letter to
`$menuSections`; it must not clash with an option key (`A`) or `Q`.

---

## Output helpers

**Rule: report what happened with `Write-Status`, and mark sections with `Write-Banner`.**
Don't pair `Write-Host` with a separate log call. Plain `Write-Host` is fine for text that
belongs only on screen, such as prompt help, menus and summary tables.

**Never send secrets through `Write-Status` or `Write-Banner`:** both write to the log
file. Zulu's `-GenerateOnly` prints generated passwords with `Write-Host` on purpose.

`Enable-AdvancedAuditing` and the `Dev/` backup and restore functions still use
`Write-Host` for status; convert them when you touch them.

### `Write-Status` (`Messages/Write-Status.ps1`)

```powershell
Write-Status [-Message] <string> [-Level Info|Success|Warning|Error|Skip] [-Tag <string>]
             [-LogOnly] [-NoLog] [-LogMessage <string>]
```

- **Screen output** is `  [LEVEL] message`, colored by level: Info is white, Success
  green, Warning yellow, Error red, Skip dark gray. **Log output** is
  `[time] [LEVEL] message`.
- **`-Tag`** replaces the level on screen with a subsystem name (`[WinRM]`, `[RDP]`,
  `[Users 1/4]`). The log line gets `[Tag]` in front of the message.
- **`-LogOnly`** writes details not worth showing on screen. **`-NoLog`** writes to the
  screen only.
- **`-LogMessage`** logs different text from what the screen shows, usually more detail
  or a stable phrase that's easy to grep for.

```powershell
Write-Status -Level Success -Tag RDP "TermService stopped"
Write-Status -Level Warning "Could not remove $name" -LogMessage "Could not remove $name from ${group}: $msg"
Write-Status -LogOnly "Loaded ports configuration from ports.json"
```

### `Write-Banner` (`Messages/Write-Banner.ps1`)

```powershell
Write-Banner [-Title] <string> [-Body <string[]>] [-Style Box|Inline] [-Color <ConsoleColor>]
             [-Width <int>] [-Log]
```

- **`Box`** (the default) is for sections. It draws a 40-character `=` border with the
  title in green and any `-Body` lines in white, and always writes
  `===== Title =====` to the log as a section marker.
- **`Inline`** prints `=== Title ===` in cyan, for sub-sections, lists and menus. It only
  writes to the log with `-Log`, since most inline banners are just display grouping.

### `Write-Log` (`Messages/Log.ps1`, internal)

`Write-Log` appends one timestamped line to `$script:LogFile`, and does nothing if there
is no log file. It isn't exported. Call `Write-Status -LogOnly` instead. Only
`Write-Status`, `Write-Banner` and `Log.ps1` itself call it.

### Summary and status

- **`Set-OperationStatus <key> <text>`** records a line for the summary.
  `Invoke-HardeningOperation` does this automatically.
- **`Reset-OperationStatus`** marks every tracked operation "Not executed".
- **`Show-OperationSummary`** prints the OS, each operation's status, the counters,
  skipped operations with reasons, and warnings. Menu option `0` calls it. Status
  colors come from the text: a status starting with "Failed" is red, one starting with
  "Skipped" is yellow, and "successfully" is green. Start failure and skip statuses
  with those words.

---

## Prompt helpers

**Every prompt needs a parameter that bypasses it.** There is no `Read-Host` over WinRM,
and the full run must be able to go without any prompts. For example, `-SaltPhrase`
bypasses Zulu's prompt, `-SplunkIP` / `-SkipSplunk` the Splunk IP, and `-FirewallPorts`
/ `-NonInteractive` the port picker.

### `Read-Choice` (`Messages/Read-Choice.ps1`)

This is the general-purpose picker used by the menu, the port prompts, the protocol
prompt and the Splunk version prompt.

```powershell
Read-Choice -Prompt <string> [-Options <object[]>] [-Title <string>] [-Multiple]
            [-AllowCustom] [-ValidateCustom <scriptblock>] [-Default <string[]>]
            [-AllowEmpty] [-AllowQuit] [-QuitLabel <string>]
```

- **Options** are plain strings (keyed `1`, `2`, ...) or hashtables with `Key`, `Label`,
  and optionally `Value` (what gets returned; defaults to `Key`), `Section` (a header,
  printed whenever it changes) and `Hidden` (`$true`: not listed, but its key can still
  be typed). Keys are case-insensitive.
- **`-Multiple`** accepts several keys separated by commas or spaces, and numeric ranges
  like `5-8`. A range selects the options (hidden ones included) whose keys fall inside
  it; it doesn't pass the range through as a value.
- **`-Hint`** replaces the generated input hint shown under the list.
- **`-AllowCustom`** accepts values that aren't listed. Each goes through
  `-ValidateCustom`, which returns a normalized value or throws to reject the input.
- **`-Default`** lists the keys selected when the user presses Enter; they're marked `*`
  in the list.
- **`-AllowEmpty`** (with `-Multiple`) makes Enter return an empty array.
- **`-AllowQuit`** adds `Q`, which returns `$null`.
- Invalid input is explained and the prompt repeats. Nothing is returned until the input
  is valid.
- **Return value.** One value normally. With `-Multiple`, an array wrapped with the
  comma operator (`return ,$unique`), in the order typed, with duplicates removed.
  **Assign the result directly:** `$ports = Read-Choice ...`. Don't write
  `@(Read-Choice ...)`, which nests the array inside another one.

```powershell
$ports = Read-Choice -Title "Ports to open" -Prompt "Ports" -Options @(Get-FirewallPortOptions) `
    -Multiple -AllowCustom -AllowQuit `
    -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
if ($null -eq $ports) { return }   # Q
```

### `Read-YesNo`, `Read-HostAddress` and `Read-SecretInput` (`Messages/Prompts.ps1`)

- **`Read-YesNo -Message "Continue? (y/n) "`** loops until the answer is `y` or `n` and
  returns it. `-Force` returns `'y'` without asking.
- **`Read-HostAddress -Prompt "Splunk server IP"`** asks until the answer is an IPv4
  address, an IPv6 address or a host name (checked with `Test-HostAddress`). It is built
  on `Read-Choice -AllowCustom`.
- **`Read-SecretInput "Enter seed phrase: "`** reads masked input and returns plain text.
  It's used for the Zulu seed and account passwords.

---

## Other helpers

| Helper | File | Use it for |
|---|---|---|
| `ConvertTo-PortList -Ports <string[]>` | `Helpers/` | Parsing port input (`"80, 443"`, `@("80","443")`, `80,443`) into validated ints; throws on bad input. Returns `,$result`, so assign it directly |
| `Set-RegistryValue -Path -Name -Value -PropertyType [-CreatePathIfMissing]` | `Helpers/` | Registry writes: creates or updates the value and reports it with `Write-Status`. Without `-CreatePathIfMissing`, a missing key is a skip; a write failure throws |
| `Get-FileFromUrl -Url -OutputPath` | `Helpers/` | Downloads over TLS 1.2 with the progress bar hidden; returns `$true` / `$false` |
| `New-Password` / `ConvertTo-WordIndex` | `Helpers/` | Zulu's deterministic passwords: MD5 of seed + username, mapped onto `wordlist.txt`. **Don't change the algorithm or the wordlist.** Teammates regenerate the same passwords on other machines |
| `Test-IsAdministrator` | `Helpers/` | Whether the session is elevated |
| `Test-HostAddress -Address` | `Helpers/` | Whether a string is a full IPv4 address, an IPv6 address or a host name. Stricter than `[ipaddress]::TryParse`, which accepts `"10"` |
| `Test-Prerequisites` | `Helpers/` | Pre-flight: admin (throws if not), OS and PowerShell version (warnings) |
| `Get-FirewallPortOptions [-IsDC]` | `Network/` | The suggested scored and AD ports as `Read-Choice` options; `-IsDC` marks the AD ports as defaults |
| `Get-FirewallPortDescription -Port` | `Network/Add-FirewallPort.ps1` | Port name from `ports.json`, with a fallback (internal) |
| `Set-FirewallAllowRule -Port -Protocol` | `Network/Add-FirewallPort.ps1` | Creates or re-enables `Allow <proto> <port>` without duplicating it, and warns about Block rules that would override it (internal). Use it rather than calling `New-NetFirewallRule` directly |
| `Show-Users` | `Helpers/` | Lists enabled and disabled users with their groups (slow on a DC: one query per group per user) |

---

## PowerShell pitfalls that have bitten this code

These have all caused real bugs here.

1. **Array unrolling.** A function that returns an array sends it down the pipeline one
   item at a time; a one-element array arrives as a scalar, an empty one as `$null`.
   `ConvertTo-PortList` and `Read-Choice -Multiple` return `,$array` to prevent that.
   Assign the result directly (`$x = ConvertTo-PortList ...`). To pipe it, add
   parentheses first (`(ConvertTo-PortList ...) | Sort-Object`). Wrapping it in `@()`
   nests it inside another array.
2. **`$null` in arrays.** `@($null).Count` is 1, and `[int]"$null"` is `0`. Filter
   optional parameters before combining them:
   `@($a) + @($b) | Where-Object { $null -ne $_ }`.
3. **Non-terminating errors skip `catch`.** `Get-LocalUser -Name nobody | Set-LocalUser ...`
   writes an error, passes nothing down the pipeline, and throws nothing. The step
   "succeeds" without changing anything. Use `-ErrorAction Stop` on the first command in
   the pipeline, not only the last.
4. **Native commands never throw.** `netsh`, `auditpol`, `reg` and `wusa` report failure
   only through `$LASTEXITCODE` (or, for `Start-Process -PassThru`, `.ExitCode`).
   Wrapping them in `try` does nothing.
5. **`$Error` inside a module is not `$global:Error`.** Errors land in `$global:Error`.
   Code that removes an expected error, or counts a run's errors, uses `$global:Error`
   (see `Set-RestrictedExecutionPolicy` and `Invoke-WindowsHardening`).
6. **`switch` doesn't stop at the first match.** Without `break`, every matching case
   runs. `switch -Wildcard` can therefore return two values, an array.
7. **PowerShell 5.1 only.** No `??`, `?:`, `&&`, `||` or `-Parallel`, and nothing from
   PowerShell 7. See the README's *PS 5.1 Compatibility* section.
8. **Encoding.** PowerShell 5.1 reads a `.ps1` without a byte-order mark as ANSI. Keep
   source files ASCII-only (no curly quotes, em dashes or box-drawing characters), or
   save them as UTF-8 *with* a BOM.
9. **The ActiveDirectory module.** `Get-ADUser -Identity x` throws for a missing user
   even with `-ErrorAction SilentlyContinue`. To test whether a user exists, use
   `Get-ADUser -Filter "SamAccountName -eq 'x'"`.

---

## Testing

There is no automated test suite. What works:

**Parse check and export check.** This runs on Linux with `pwsh`, too:

```powershell
Get-ChildItem ./WindowsHardening -Recurse -Include *.ps1, *.psm1, *.psd1 | ForEach-Object {
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors) | Out-Null
    if ($errors) { "$($_.Name): $($errors[0])" }
}
Import-Module ./WindowsHardening -Force
$m = Get-Module WindowsHardening
(Import-PowerShellDataFile ./WindowsHardening/WindowsHardening.psd1).FunctionsToExport |
    Where-Object { -not (& $m { param($n) Get-Command $n -CommandType Function -ErrorAction Ignore } $_) }
# ^ prints any manifest entry with no matching function
```

**Logic tests with stand-ins.** Run code inside the module's scope and replace the
system cmdlets with fake versions, so the logic can run on any machine:

```powershell
& (Get-Module WindowsHardening) {
    function Invoke-HardeningOperation { param($OperationName, $ScriptBlock) & $ScriptBlock }
    function Set-NetFirewallProfile {}; function Get-NetFirewallRule {}; function Disable-NetFirewallRule {}
    function netsh {}                                                  # native commands can be faked too
    function Set-FirewallAllowRule { param($Port, $Protocol) Write-Host "would allow $Protocol $Port" }
    function Read-Host { param($p) '1433 8080' }                       # scripted input
    $script:HardeningContext.OS = [pscustomobject]@{ IsDomainController = $true }
    $script:HardeningContext.LogPath = $env:TEMP
    Set-FirewallConfiguration -NonInteractive -Prompt
}
```

Functions defined inside `& (Get-Module ...) { }` override the real cmdlets for code
running in the module, because PowerShell prefers functions over cmdlets. Re-import the
module afterwards to get rid of the fakes.

**The real test** is a snapshot of a Windows VM: one DC and one member or standalone
machine. Use `loader.ps1 -Ref <your-branch>` to pull your branch. Take the snapshot
first. `Restore-WindowsState` is experimental and is **not** a substitute for one.

---

## Checklist: adding a new hardening step

1. Create `Public/<Section>/<Verb-Noun>.ps1` with `[CmdletBinding()]` and parameters for
   anything it would otherwise prompt for.
2. Wrap the body in `Invoke-HardeningOperation -OperationName "<Name>"`. Add
   `-OSCompatibility` if the step only applies to some versions. Throw on failure. Use
   `-ErrorAction Stop` where a failure matters.
3. Report with `Write-Status` / `Write-Banner`, not paired `Write-Host` and log calls.
4. Add `"<Name>"` to `$script:TrackedOperations` in `Messages/Log.ps1`.
5. Add the function to `FunctionsToExport` in `WindowsHardening.psd1`.
6. If it belongs in the full run, call it from the section orchestrator: set
   `$script:NextStepLabel`, add a `-Skip<Step>` switch, and renumber the step labels
   (`1/3`, `2/3`, ...).
7. If it belongs in the menu, add a `$menuOptions` entry and an `Invoke-MenuAction` case.
8. Update the README: the function section, the parameter table, and the menu range if
   it changed.
9. Run the parse and export check, then test it on a VM, both as a DC and as a
   non-DC machine.
