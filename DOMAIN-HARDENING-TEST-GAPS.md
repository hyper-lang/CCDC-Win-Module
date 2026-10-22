# Invoke-DomainHardening: known test gaps

Date: 2026-10-22. Companion to `DOMAIN-HARDENING-TEST-RESULTS.md`, which records what
was tested and the evidence. This file lists what was **not** covered, so it can be
closed before relying on the domain workflow in competition.

## Covered (for context)

- GPO linking, computer-account security filtering, and baseline enforcement on Server
  2016, 2019, 2022, and 2025 DCs, with member servers and Windows 10/11 clients.
- nmap scans from inside the lab subnet and from an outside source, including full
  65535-port TCP scans, plus outbound connection tests.
- Functional checks:
  - FTP passive and active transfers.
  - SSH banner.
  - Authenticated SMB share listing.
  - WinRM HTTP response.
  - RDP TCP handshake.
  - SYSVOL (DFSR) and AD replication both ways between two DCs, with a DFSR negative
    control.
  - NTP resync from members and from a non-PDC DC.
- Enforcement against a rogue OU GPO and against Block Inheritance.
- Reruns, including upgrading an existing unenforced deployment. All runs had 0
  failed operations except the transient error in gap 5.

## Gaps

1. **The final code has not run from a clean snapshot.** Baseline enforcement, the
   SSH/RDP/FTP/SMB roles, and port ranges were tested as reruns over an
   already-hardened lab. The last from-scratch run predates them. *Close by:* roll
   back to `clean`, promote a second DC, then run the final code with every role and a
   ranged port rule. Repeat the nmap, service, replication, and NTP checks.
2. **The interactive prompts were never exercised.** Every lab run used `-NoPrompt`
   with `-RoleServers`. The role picker now asks about nine roles in sequence.
   *Close by:* a manual run on a DC, choosing several roles and leaving some empty.
3. **Password, Zulu, CCDC-user, and Splunk steps were skipped.** Every run used
   `-SkipPasswordChange -SkipSplunk`. The Administrator password change, Zulu
   rotation, CCDC account creation, and Splunk install never ran inside
   `Invoke-DomainHardening`. *Close by:* a manual full run on a lab DC.
4. **Multi-DC coverage is thin.** Only one two-DC domain was tested (Server 2022,
   single site, DFSR). Not covered:
   - 2016 and 2019 DC pairs.
   - Mixed-version DC pairs.
   - Multiple AD sites.
   - Domains that still replicate SYSVOL with **FRS**, which the DFSR rules do not
     cover.
   - A second DC promoted *after* hardening; promotion needs RPC from the new
     server, which the member policy blocks.
5. **An unexplained transient failure.** The first run on the two-DC domain failed
   one step: `Import-GPO` for `Domain GPO Update Interval` returned "There is no
   such object on the server" (0x80072030). The GPO was intact and identical on both
   DCs, and two immediate reruns were clean. A run that hits it reports one failed
   operation; rerunning resolves it.
6. **The effects of the DC outbound Block are only partly explored.**
   - Checked: DNS forwarding, NTP, Splunk 9997, outbound 80/443, gpupdate, and AD/DFSR
     replication.
   - Not checked: Windows Update beyond 80/443 (for example Delivery Optimization),
     CRL and OCSP checks on other ports, AD CS, DHCP server on a DC, cross-site
     replication, and trusts.
   - Known blocked from a DC unless an exception is added: WinRM or `Invoke-Command`
     to members, outbound RDP, and `repadmin` against a remote DC.
7. **Smaller untested pieces:**
   - RDP UDP 3389 was never tested end to end (TCP handshake only).
   - The FTP role was tested only with IIS FTP. The data rules match only the
     `ftpsvc` service, and the run prints a warning about this.
   - The Linux member (`lin22`) was not part of any run.
   - PDC time sync to an external source: the lab PDCs use the local clock. Only
     reachability of `time.windows.com` over UDP 123 was verified.
   - Enforcement does not protect against an attacker who already has Domain
     Admin; they can unlink or edit the GPOs.

## Lab notes

The harness is in `windows-ralph/proxmox-windows-templates/tools/nmap-validation/` and
raw results in `logs/nmap-validation/`. A rollback to the `clean` snapshot removes the
lab leftovers:

- srv2022 promoted to a DC.
- Rogue and NoInherit OUs in C25.
- IIS FTP on srv2019.
- Test listeners on every VM.
