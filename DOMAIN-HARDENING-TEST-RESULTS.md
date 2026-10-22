# Invoke-DomainHardening lab results

Date: 2026-10-22

## Result

The final module was deployed and exercised across the four lab domains: Windows
Server 2016, 2019, 2022, and 2025. Each domain run completed with **0 failed
operations**, **0 nonterminating error records**, and a successful `gpupdate /force`.
The final ActiveStore check also ran on all ten lab VMs: the four DCs, four paired
member servers, Windows 10, and Windows 11.

The port exception functions were tested in each domain. The run added inbound TCP
54321 for the selected member server, refreshed policy, confirmed the rule was
effective there, removed the rule GPO, refreshed again, and confirmed the rule was
gone. The test rule was removed from every lab domain.

The lab harness used `-SkipPasswordChange` and `-SkipSplunk`; administrator/Zulu
password changes, CCDC account creation, and Splunk installation were not exercised.
The GPO linking, role firewall policies, group policy refresh, effective firewall
state, and port-rule add/remove lifecycle were exercised.

The test runner reset all ten VMs to their clean snapshots before testing. They are
currently running the resulting test policies so the lab remains available for
inspection. Detailed logs are in the lab's `logs` directory, including
`domain-hardening-dc*.log`, `policy-verify-vm*.log`, and `port-rule-*.log`.

## nmap validation (2026-10-22, afternoon)

The ActiveStore checks above showed which rules were present. They did not show
whether traffic actually got through. The second test put real listeners behind
the policy and scanned them from the jump box.

**Method.** All ten VMs were reset to `clean`. Every Windows host got TCP
listeners on 21, 25, 80, 110, 143, 443, 587, 993, 995, 1433, 3306, 5432, 6379,
8080, 9997, 33060, and 54321, so a filtered port can be told apart from a port
with nothing behind it. Each domain got a different role mix:

| Domain | Role assignments | Port rule |
|---|---|---|
| C16 | srv2016 = Web | `Lab-Temp` TCP 54321, Any, on srv2016; removed by a second run |
| C19 | srv2019 = Database | none |
| C22 | srv2022 = Mail + WinRM | none |
| C25 | srv2025 = Database + Web + Mail + WinRM | `Lab-Win10` TCP 54321, LocalSubnet, on win10 |

`Invoke-DomainHardening -SkipPasswordChange -SkipSplunk -NoPrompt` ran on each DC.
Then `gpupdate /force` ran on all VMs. nmap (`-sS -Pn`) scanned from 172.30.0.1,
inside the lab subnet, and from 10.99.99.1, a source outside it, which tests
`LocalSubnet` scoping. The final state also got a full 65535-port TCP scan and a
UDP scan of 53/88/123/137/389/464.

**Two bugs found and fixed:**

1. **Three of four DCs had no effective firewall.** `DC Allow AD` enabled only the
   Domain profile. dc2019, dc2022, and dc2025 booted with their NIC on the
   **Public** network profile: NLA ran before AD DS was ready, which is common on
   DCs. Every listener on those DCs was open from both sources, including RDP,
   SSH, WinRM, ADWS, and all decoy ports. dc2016 happened to come up as
   DomainAuthenticated and was filtered correctly.
   *First fix:* `Link-DcAllowAdGpo` set Domain, Private, and Public to inbound
   Block / outbound Allow. This was superseded by the layered design described
   under "Layered DC firewall" below.
2. **The WinRM preservation rule never matched.** `Add-CcdcWinRMAccessGpo` created
   the rule with `-Service WinRM`. WinRM receives traffic through HTTP.sys, which
   runs as the System process (PID 4), so 5985 stayed filtered on the selected
   servers even from inside the subnet. *Fix:* `-Program 'System'`, which matches
   Windows' built-in WinRM rule.

A cosmetic fix: `Remove-DomainFirewallPortRule` now pipes `Remove-GPLink` to
`Out-Null`. Before, the GPO object printed in the middle of the run output.

**Result after the fixes.** The fixed module was rerun on all four DCs. The rerun
was idempotent: 0 failed operations and 0 `$Error` records on every DC. Open TCP
ports from a full 65535-port scan:

| Host | Open from inside the subnet | Additionally filtered from outside |
|---|---|---|
| dc2016 / dc2019 / dc2022 / dc2025 | 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, dynamic RPC 49xxx | 135 (LocalSubnet) |
| srv2016 (Web) | 80, 443 | none |
| srv2019 (Database) | 3306, 33060 | none |
| srv2022 (Mail + WinRM) | 25, 80, 110, 143, 443, 587, 993, 995, 5985 | 5985 |
| srv2025 (all roles) | union of the above, 25-33060 plus 5985 | 5985 |
| win10 (port rule) | 54321 | 54321 |
| win11 | none | none |

- Everything else was filtered, including SSH, RDP, 5986, 47001, ADWS 9389, and
  all decoy listeners.
- The `Lab-Temp` 54321 rule was open on srv2016 after run 1 and filtered after the
  removal run.
- WinRM returned HTTP 411 on srv2022 and srv2025, so the service really answers
  there. On srv2019 it timed out.
- UDP: the DCs answered on 53, 88, 123, 137, and 389.

Outbound, tested from each host to listeners on the jump box:

- Non-DCs reached 9997 (Splunk), 80, 443, and DNS. They were blocked on 9998,
  8443, and 22.
- Port 25 was allowed only on the mail-role servers (srv2022, srv2025).
- DCs allowed all outbound traffic.
- `gpupdate` succeeded on every member after hardening, so DC-to-member AD traffic
  still works.

**Observations, not changed:**

- ADWS (9389) is closed on DCs. AD PowerShell and ADAC can't reach a DC from
  other machines.
- `Remove-AdminUsers` removes Domain Admins and Enterprise Admins from the DC's
  builtin Administrators group.
- The WinRM rule is Domain-profile only. A member that falls back to Public
  loses WinRM, which fails closed.

The harness and raw scans are in the lab folder, under
`tools/nmap-validation/` and `logs/nmap-validation/`.

## Layered DC firewall (2026-10-22, evening)

**Why.** Upstream `AD-Hardening.ps1` linked `Domain Allow AD + Core + Default Block`
at the root with no filter, so DCs received it too. The bundled `DC Allow AD` backup
has no profile settings at all, only allow rules. The Block GPO also contains
DC-only rules: Active Directory Domain Controller TCP-Out and UDP-Out. Together
these show the design: the Block GPO enforces on every computer, and `DC Allow AD`
layers the DC inbound rules on top. The module's `Domain Computers` filter had
excluded DCs from the Block GPO, and that exclusion caused the Public-profile bug.

**Change.**

- `Link-DomainFirewallGpo` filters the Block GPO to `Authenticated Users`. This
  restores DCs and replaces the filter left by older runs. After import, it adds
  `CCDC NTP (UDP-Out)`, remote port 123.
- `Link-DcAllowAdGpo` no longer sets profiles. It adds
  `CCDC DFS Replication (RPC-In)` and `(TCP-Out)`, both limited to
  `%SystemRoot%\system32\dfsrs.exe`.
- New helper: `Set-CcdcGpoFirewallRule`.

DCs now run all profiles with inbound and outbound Block, whatever profile NLA
picks.

**NTP was already broken for members.** Under the earlier policy, `w32tm /resync`
failed on srv2019 and win10 with "no time data". Their NTP queries to the DC timed
out because members' default outbound Block had no UDP 123 rule. Kerberos would
start failing once clocks drifted past 5 minutes.

**Test.** All VMs were reset to `clean`. srv2022 was promoted to a second C22 DC so
real SYSVOL and AD replication could be tested. The setup and nmap method were the
same as above. After the forced KCC and DFSR polling a fresh promotion needs, the
pre-hardening baseline replicated both ways. 0 failed operations and 0 `$Error`
records on all four DCs.

| Check | Result |
|---|---|
| DC firewall profiles | All three enabled, inbound and outbound Block, on all five DCs. dc2019, dc2022, and dc2025 were on Public. |
| SYSVOL (DFSR) replication, both directions | Replicated in 4 s |
| AD replication, both directions | Replicated in 7-13 s |
| Negative control: DFSR rules disabled | SYSVOL stopped both ways; AD still replicated |
| NTP | All members and the non-PDC DC (srv2022) resync from their DC. PDCs reach time.windows.com over UDP 123. PDC "no time data" is lab config (Local CMOS Clock source), same with the firewall off. win11's W32Time service is not running in the lab. |
| DC outbound | 9997, 80, 443, and DNS forwarding work; 9998, 8443, 22, and 25 blocked |
| DC inbound (full scan) | 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, dynamic RPC (now including DFSR's endpoint). 135 is filtered from outside the subnet. UDP: 53, 88, 123, 137, 389. |
| Members and clients | Same as the previous section |

**SYSVOL deadlock seen during the negative control.** Firewall rules live in the
GPO's SYSVOL half, and a DC applies policy from its own SYSVOL copy. After the DFSR
rules were disabled and then re-enabled on dc2022, srv2022 never received the fix,
because the fix needs DFSR to arrive. The fix was to copy the GPO folder over SMB,
which outbound 445 allows, and refresh policy:

```powershell
$id = '{' + (Get-GPO -Name 'DC Allow AD' -Server <good DC>).Id + '}'
robocopy "\\<good DC>\SYSVOL\<domain>\Policies\$id" "C:\Windows\SYSVOL\domain\Policies\$id" /E /IS
gpupdate /force
```

DFSR reconnected within 30 s, and the files stuck during the outage replicated.
A normal first run does not hit this, because other DCs receive the complete GPO
before their firewall changes. Only a later GPO version that breaks DFSR does.

**Consequences of DC outbound Block to keep in mind:**

- Admin tools that run *on* a DC and reach other hosts are blocked unless a rule
  covers them. This includes WinRM / `Invoke-Command` to members (5985), RDP
  out, and `repadmin` against a remote DC. Add these with
  `Add-DomainFirewallPortRule -Direction Outbound -ComputerName <DC>` if needed.
- Old domains that still replicate SYSVOL with FRS (not DFSR) are not covered.

## Service roles and enforced baseline (2026-10-22, night)

**Change.**

- New roles WinRM, SSH, RDP, FTP, and SMB, all built from one table in
  `GpoHelpers.ps1` (`Add-CcdcServiceRoleGpo`).
- New public function `Link-ServerServiceGpo`. `Link-ServerWinRMGpo` now wraps it.
- New `Invoke-DomainHardening -RoleRemoteAddress` parameter for per-role scope
  overrides.
- The baseline links are enforced: Block firewall, Splomk, Update Interval,
  Good-GPO, and DC Allow AD. Role and port-rule links stay unenforced.

**Test.** The new code was rerun over the existing unenforced deployment, which
exercises the upgrade path:

| Domain | Roles |
|---|---|
| C16 | srv2016: Web, SSH, RDP (scope `LocalSubnet`) |
| C19 | srv2019: Database, FTP (real IIS FTP installed), SMB |
| C25 | srv2025: Database, Web, Mail, WinRM, SMB |

For the enforcement test, two C25 computers were moved before the rerun:

- win11 went into an OU linked to a `Rogue Firewall Off` GPO (all profiles
  disabled, inbound Allow).
- win10 went into an OU with Block Inheritance.

| Check | Result |
|---|---|
| Before enforcement | Both win10 and win11 had the firewall **off**; every listener was open |
| After enforcement | Both were fully filtered: the enforced baseline beat the rogue GPO and ignored Block Inheritance. win10's unenforced 54321 port-rule GPO was blocked, as designed. |
| SSH (srv2016) | 22 open from both sources; the banner was returned |
| RDP (srv2016, LocalSubnet override) | 3389 open from inside the subnet only; TLS handshake completed |
| FTP (srv2019, IIS) | Passive and active transfers both worked, including passive from outside the subnet. A full 65535-port scan showed only 21, 445, 3306, and 33060, even though 1433, 5432, 6379, 8080, and others were listening, so the passive rule's `ftpsvc` scope holds. |
| SMB (srv2019, srv2025) | 445 open; authenticated `smbclient -L` share listing worked |
| Runs | C16, C19, and C25: 0 failed operations. C22 (two DCs): see below. |

**FTP findings.** With only TCP 21 open, both passive and active transfers failed.
Enabling Windows stateful FTP through the GPO (`DisableStatefulFTP=0`, confirmed in
RSOP) did not change the effective setting. Enabling it locally fixed active mode
only. That is why the role ships explicit passive and active data rules scoped to
`ftpsvc`, which is IIS-only.

**Port ranges.** `Add-DomainFirewallPortRule -Port` now takes ports and inclusive
ranges (`21, '50000-50100'`), validated to 1-65535 with low <= high. In the lab,
`-Port 54321, '50000-50100'` on srv2019 produced one rule with the entries
`54321 | 50000-50100`. nmap showed 50000, 50050, 50100, and 54321 open, and 49999 and
50101 filtered. After `Remove-DomainFirewallPortRule`, the range was filtered again.

**Transient error on C22.** The first run on the two-DC domain failed one step:
`Import-GPO` for `Domain GPO Update Interval` returned "There is no such object on
the server" (0x80072030). The GPO was intact and identical on both DCs. Two
immediate reruns were clean. The cause was not identified; rerunning resolves it.

## Changes covered by the test

- Linked `Domain Splomk` at the domain root for `Domain Computers` and `Domain
  Controllers`. Its outbound TCP 9997 rule applied to every DC, member server, and
  Windows client in the lab.
- Enabled the DCs' Domain firewall profile in the `DC Allow AD` GPO, with default
  inbound blocked and outbound allowed. The bundled backup contains inbound AD rules
  but no complete outbound allow list, so outbound remains allowed by default.
- Added `Add-DomainFirewallPortRule` and `Remove-DomainFirewallPortRule`. Each named
  exception gets a dedicated root-linked GPO filtered to its computer accounts.
  This handles the domain firewall policy's disabled local rule merging. The
  functions are exported and can be called on their own or through
  `Invoke-DomainHardening` parameters `-FirewallPortRulesToAdd` and
  `-FirewallPortRulesToRemove`.
- Removed Splunk from the per-server role picker because its outbound policy now
  applies domain-wide. Database, web, mail, and WinRM remain individually selected.
- Changed absent GPO/rule lookups to ignore the expected not-found result. The final
  lab runs recorded no nonterminating errors.

## Effective firewall policy observed in the lab

Firewall rules allow traffic only when the firewall profile is enabled and a
matching service is listening. The table below lists the enabled GPO rules observed
in each machine's ActiveStore; it does not claim that an application is listening
on every allowed port.

| Scope / role | Direction and protocol | Allowed ports | Remote scope |
|---|---|---|---|
| All domain computers and DCs: Splunk (`Domain Splomk`) | Outbound TCP | Remote port 9997 | Any |
| Non-DC domain computers: core domain policy | Outbound TCP | Remote ports 53, 88, 389, 445, 80, 443 | Any |
| Non-DC domain computers: core domain policy | Outbound UDP | Remote ports 53, 88, 389 | Any |
| DCs: `DC Allow AD` | Inbound TCP | 53, 88, 135/RPC endpoint mapper, 139, 389, 445, 464, 636, 3268, 3269 | Mostly Any; SMB/RPC rules include LocalSubnet restrictions |
| DCs: `DC Allow AD` | Inbound UDP | 53, 88, 123, 137, 138, 389, 445, 464 | Mostly Any; some built-in rules use LocalSubnet |
| Database role | Inbound TCP | Local ports 3306, 33060 | Any (the backup has no client allow-list) |
| Web role | Inbound TCP | Local ports 80, 443 | Any |
| Mail role | Inbound TCP | Local ports 25, 80, 443, 143, 993, 110, 995, 587 | Any |
| Mail role | Outbound TCP | Remote port 25 | Any |
| Selected WinRM role | Inbound TCP | Local ports 5985, 5986 | LocalSubnet by the CCDC GPO (did not match traffic until the -Program fix; see the nmap validation section) |

The DC policy also contains RPC rules using the Windows `RPC`/`RPC-EPMap` service
filters; these are not represented as one fixed numeric dynamic RPC port in the
ActiveStore output. Other built-in Windows core networking rules (including ICMP
and DHCP) are present as well.

On all four member servers and both Windows clients, the Domain, Private, and Public
firewall profiles were enabled with inbound and outbound defaults set to Block. On
the four DCs, the Domain profile was enabled with inbound Block and outbound Allow;
Private and Public remained disabled. (This was a bug; see the nmap validation section.) The domain-wide Splunk rule is present on DCs
too, though outbound traffic on a DC is already allowed by its default policy.

The role GPOs were applied to the selected member server in each domain. The DCs and
Windows clients were filtered out of those role GPOs. The member server in each lab
domain received the database, web, mail, and WinRM rules during this test.

## Reusable port exception examples

```powershell
# Inbound TCP 5432 for two database servers, limited to the local subnet
Add-DomainFirewallPortRule -Name 'Postgres' -ComputerName DB01,DB02 `
    -Port 5432 -Protocol TCP -Direction Inbound -RemoteAddress LocalSubnet

# Remove the dedicated GPO and its rule
Remove-DomainFirewallPortRule -Name 'Postgres'
```

For an outbound rule, `-Port` is the remote port. If `-RemoteAddress` is omitted,
the rule allows that port to/from any remote address permitted by the rest of the
network path.
