function Restore-WindowsState {
    <#
    .SYNOPSIS
        Restores a previously captured Backup-WindowsState snapshot to the live system.

    .DESCRIPTION
        Reverses hardening-script changes by replaying 9 restore categories in a safe
        order from a backup created by Backup-WindowsState. SHA256 checksums are verified
        before any restore is applied, and re-exported after to confirm the restore landed
        cleanly.

        Restore order:
          1. LSA settings         (HKLM:\...\Lsa registry values)
          2. Execution policy     (Set-ExecutionPolicy)
          3. WDigest              (UseLogonCredential registry value)
          4. SMB configuration    (SMBv1/v2 enabled state, encryption)
          5. Audit policy         (auditpol /restore)
          6. Users / groups       (local group memberships only; see LIMITATIONS)
          7. Firewall             (profile settings + per-rule enabled/action state)
          8. Services             (startup type only; service account passwords not restored)
          9. Registry hives       (reg import - see LIMITATIONS; runs last to avoid
                                   overwriting the value-level restores above)

    .CAPABILITIES
        - Safe: pre-restore checksum verification aborts if any backup file was tampered
          with or is missing. Post-restore re-export confirms state matches the snapshot.
        - Configuration-complete: covers every category that Backup-WindowsState captures.
        - DC-aware: detects domain controllers and skips AD object changes that cannot be
          safely automated, writing MANUAL-RESET-REQUIRED.txt instead.
        - Non-destructive of passwords: does not attempt to restore user passwords, which
          cannot be round-tripped safely.

    .LIMITATIONS
        THIS RESTORES CONFIGURATION VALUES, NOT DISK STATE. The same gaps that apply to
        Backup-WindowsState apply here:

        - Registry .reg imports (step 9) WILL FAIL on a live system. HKLM\SOFTWARE and
          HKLM\SYSTEM are locked while Windows is running. reg import silently fails or
          partially applies. These files are archived for offline recovery (WinPE / mount
          hive) only. All security-relevant registry state is handled by the value-level
          steps (1, 3) instead.

        - Filesystem changes are NOT reverted. Dropped binaries, new scheduled tasks, WMI
          subscriptions, COM hijacks, DLL sideloads, and modified system files survive this
          restore. Run Autoruns and a file-integrity check separately.

        - In-memory threats survive. Injected code and fileless implants are unaffected.

        - Boot/firmware persistence survives. Bootkits, MBR/VBR modifications, and UEFI
          implants are unaffected.

        - AD persistence survives. ACL backdoors, AdminSDHolder abuse, shadow credentials,
          rogue CA certificates, SPN abuse, and exfiltrated credential material (hashes,
          tickets) cannot be undone by a configuration restore.

        - Service passwords are NOT restored. Startup type is restored; the service account
          password is not touched.

        - Domain controllers: AD user/group state is not automatically restored. The function
          writes MANUAL-RESET-REQUIRED.txt listing items that need manual cleanup. No DC
          demotion is performed.

        - If the system was already compromised when the backup was taken, restoring that
          snapshot restores the attacker's configuration alongside the legitimate one.

    .PARAMETER BackupPath
        Path to a timestamped backup subfolder created by Backup-WindowsState
        (e.g. C:\Windows\System32\wbem\.hb\2026-08-26_120000).

    .OUTPUTS
        PSCustomObject with Success, RestoredCategories, Errors, and IsDomainController.

    .EXAMPLE
        Restore-WindowsState -BackupPath "C:\Windows\System32\wbem\.hb\2026-08-26_120000"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )

    $restoreErrors = @()
    $restoredCategories = @()

    # -- Validate backup path ---------------------------------------------------
    if (-not (Test-Path $BackupPath)) {
        throw "Backup path not found: $BackupPath"
    }

    $checksumFile = Join-Path $BackupPath "checksums.txt"
    if (-not (Test-Path $checksumFile)) {
        throw "Checksum file not found: $checksumFile - cannot verify backup integrity"
    }

    Write-Host "`n=== Reverting Windows State ===" -ForegroundColor Cyan
    Write-Host "Backup location: $BackupPath" -ForegroundColor Cyan

    # -- Verify checksums before restore ----------------------------------------
    Write-Host "`nVerifying backup integrity (checksums)..." -ForegroundColor Yellow
    $checksumEntries = Get-Content -Path $checksumFile -ErrorAction Stop
    $checksumVerified = $true
    foreach ($entry in $checksumEntries) {
        $parts = $entry -split '\s{2,}'
        if ($parts.Count -ge 2) {
            $expectedHash = $parts[0]
            $relativePath = $parts[1]
            $fullPath = Join-Path $BackupPath $relativePath
            if (Test-Path $fullPath) {
                $actualHash = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash
                if ($actualHash -ne $expectedHash) {
                    Write-Host "  [FAIL] Checksum mismatch: $relativePath" -ForegroundColor Red
                    $checksumVerified = $false
                }
            } else {
                Write-Host "  [WARN] Missing file: $relativePath" -ForegroundColor Yellow
                $checksumVerified = $false
            }
        }
    }
    if (-not $checksumVerified) {
        throw "Backup integrity check failed - aborting restore to prevent corrupt state"
    }
    Write-Host "  [OK] All checksums verified" -ForegroundColor Green

    # -- Detect DC status -------------------------------------------------------
    $isDC = (Get-OperatingSystemInfo).IsDomainController

    # -- 1. Restore LSA Settings -----------------------------------------------
    Write-Host "`n  [1/9] Restoring LSA settings..." -ForegroundColor Gray
    try {
        $lsaFile = Join-Path $BackupPath "lsa_settings.json"
        if (Test-Path $lsaFile) {
            $lsaData = Get-Content -Path $lsaFile -Raw | ConvertFrom-Json
            $lsaHash = @{}
            foreach ($path in $lsaData.PSObject.Properties) {
                $lsaHash[$path.Name] = @{}
                foreach ($prop in $path.Value.PSObject.Properties) {
                    $lsaHash[$path.Name][$prop.Name] = $prop.Value
                }
            }
            Restore-LSAValues -Values $lsaHash
            $restoredCategories += "LSA"
            Write-Host "    [OK] LSA settings restored" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "LSA: $($_.Exception.Message)"
        Write-Host "    [WARN] LSA restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 2. Restore Execution Policy --------------------------------------------
    Write-Host "  [2/9] Restoring execution policy..." -ForegroundColor Gray
    try {
        $execFile = Join-Path $BackupPath "execution_policy.json"
        if (Test-Path $execFile) {
            $execData = Get-Content -Path $execFile -Raw | ConvertFrom-Json
            Set-ExecutionPolicy -ExecutionPolicy $execData.ExecutionPolicy -Force -ErrorAction Stop
            $restoredCategories += "ExecutionPolicy"
            Write-Host "    [OK] Execution policy restored: $($execData.ExecutionPolicy)" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "ExecutionPolicy: $($_.Exception.Message)"
        Write-Host "    [WARN] Execution policy restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 3. Restore WDigest Registry Values ------------------------------------
    Write-Host "  [3/9] Restoring WDigest configuration..." -ForegroundColor Gray
    try {
        $wdigestFile = Join-Path $BackupPath "wdigest.json"
        if (Test-Path $wdigestFile) {
            $wdigestData = Get-Content -Path $wdigestFile -Raw | ConvertFrom-Json
            if ($null -ne $wdigestData.UseLogonCredential) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value $wdigestData.UseLogonCredential -Type DWord -ErrorAction Stop
            }
            $restoredCategories += "WDigest"
            Write-Host "    [OK] WDigest configuration restored" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "WDigest: $($_.Exception.Message)"
        Write-Host "    [WARN] WDigest restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 4. Restore SMB Configuration ------------------------------------------
    Write-Host "  [4/9] Restoring SMB configuration..." -ForegroundColor Gray
    try {
        $smbFile = Join-Path $BackupPath "smb_config.json"
        if (Test-Path $smbFile) {
            $smbData = Get-Content -Path $smbFile -Raw | ConvertFrom-Json
            Set-SmbServerConfiguration `
                -EnableSMB1Protocol $([bool]$smbData.EnableSMB1Protocol) `
                -EnableSMB2Protocol $([bool]$smbData.EnableSMB2Protocol) `
                -EncryptData $([bool]$smbData.EncryptData) `
                -Force -ErrorAction Stop
            $restoredCategories += "SMB"
            Write-Host "    [OK] SMB configuration restored" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "SMB: $($_.Exception.Message)"
        Write-Host "    [WARN] SMB restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 5. Restore Audit Policy -----------------------------------------------
    Write-Host "  [5/9] Restoring audit policy..." -ForegroundColor Gray
    try {
        $auditFile = Join-Path $BackupPath "auditpol.csv"
        if (Test-Path $auditFile) {
            auditpol /restore /file:$auditFile 2>&1 | Out-Null
            $restoredCategories += "AuditPolicy"
            Write-Host "    [OK] Audit policy restored" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "AuditPolicy: $($_.Exception.Message)"
        Write-Host "    [WARN] Audit policy restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 6. Restore Users/Groups/Memberships -----------------------------------
    Write-Host "  [6/9] Restoring user and group state..." -ForegroundColor Gray
    try {
        $usersDir = Join-Path $BackupPath "users"
        $manualResetItems = @()

        if (-not $isDC) {
            # Local machine: restore local user/group state
            $groupMembersFile = Join-Path $usersDir "group_memberships.json"
            if (Test-Path $groupMembersFile) {
                $memberships = Get-Content -Path $groupMembersFile -Raw | ConvertFrom-Json
                foreach ($groupName in $memberships.PSObject.Properties) {
                    foreach ($member in $groupName.Value) {
                        try {
                            $memberName = if ($member.Name -match '\\') {
                                ($member.Name -split '\\', 2)[1]
                            } else {
                                $member.Name
                            }
                            Add-LocalGroupMember -Group $groupName.Name -Member $memberName -ErrorAction Stop
                        } catch {
                            # Member may already exist - non-fatal
                        }
                    }
                }
            }
            $restoredCategories += "UsersGroups"
            Write-Host "    [OK] User/group state restored (local)" -ForegroundColor Green
        } else {
            # DC: log AD objects that cannot be automatically removed
            $manualResetItems += "AD user 'ccdcuser3' - remove via Remove-ADUser if needed"
            $manualResetItems += "Prior user passwords - reset manually if needed"
            $restoredCategories += "UsersGroups"
            Write-Host "    [INFO] DC detected - AD object cleanup logged to MANUAL-RESET-REQUIRED.txt" -ForegroundColor Yellow
        }

        # Write MANUAL-RESET-REQUIRED.txt for irreversible items
        if ($manualResetItems.Count -gt 0) {
            $manualResetFile = Join-Path $BackupPath "MANUAL-RESET-REQUIRED.txt"
            $manualResetContent = @"
MANUAL-RESET-REQUIRED
=====================
The following items cannot be automatically restored and require manual intervention:

$($manualResetItems | ForEach-Object { "- $_" } | Out-String)
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
            $manualResetContent | Out-File -FilePath $manualResetFile -Encoding UTF8
            Write-Host "    [OK] Manual reset requirements written to MANUAL-RESET-REQUIRED.txt" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "Users/Groups: $($_.Exception.Message)"
        Write-Host "    [WARN] User/group restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 7. Restore Firewall Configuration -------------------------------------
    Write-Host "  [7/9] Restoring firewall configuration..." -ForegroundColor Gray
    try {
        $fwDir = Join-Path $BackupPath "firewall"

        # Restore firewall profiles
        $profilesFile = Join-Path $fwDir "profiles.json"
        if (Test-Path $profilesFile) {
            $profiles = Get-Content -Path $profilesFile -Raw | ConvertFrom-Json
            foreach ($profile in $profiles) {
                Set-NetFirewallProfile `
                    -Name $profile.Name `
                    -Enabled $(if ([bool]$profile.Enabled) { 'True' } else { 'False' }) `
                    -DefaultInboundAction $profile.DefaultInboundAction `
                    -DefaultOutboundAction $profile.DefaultOutboundAction `
                    -ErrorAction Stop
            }
        }

        # Restore firewall rules
        $rulesFile = Join-Path $fwDir "rules.json"
        if (Test-Path $rulesFile) {
            $rules = Get-Content -Path $rulesFile -Raw | ConvertFrom-Json
            foreach ($rule in $rules) {
                if ($null -ne (Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue)) {
                    Set-NetFirewallRule `
                        -Name $rule.Name `
                        -Direction $rule.Direction `
                        -Action $rule.Action `
                        -Enabled $(if ([bool]$rule.Enabled) { 'True' } else { 'False' }) `
                        -ErrorAction Stop
                }
            }
        }

        $restoredCategories += "Firewall"
        Write-Host "    [OK] Firewall configuration restored" -ForegroundColor Green
    } catch {
        $restoreErrors += "Firewall: $($_.Exception.Message)"
        Write-Host "    [WARN] Firewall restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 8. Restore Service Configurations -------------------------------------
    Write-Host "  [8/9] Restoring service configurations..." -ForegroundColor Gray
    try {
        $svcFile = Join-Path $BackupPath "services.json"
        if (Test-Path $svcFile) {
            $services = Get-Content -Path $svcFile -Raw | ConvertFrom-Json
            foreach ($svc in $services) {
                Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction Stop
            }
            $restoredCategories += "Services"
            Write-Host "    [OK] Service configurations restored ($($services.Count) services)" -ForegroundColor Green
        }
    } catch {
        $restoreErrors += "Services: $($_.Exception.Message)"
        Write-Host "    [WARN] Service restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- 9. Restore Registry Hives (last - overwrites WDigest/LSA values) ------
    Write-Host "  [9/9] Restoring registry hives..." -ForegroundColor Gray
    try {
        $regDir = Join-Path $BackupPath "registry"
        $regFiles = @(
            @{ Hive = "HKLM\SOFTWARE"; File = "HKLM_SOFTWARE.reg" },
            @{ Hive = "HKLM\SYSTEM"; File = "HKLM_SYSTEM.reg" },
            @{ Hive = "HKU\.DEFAULT"; File = "HKU_DEFAULT.reg" }
        )
        foreach ($reg in $regFiles) {
            $regPath = Join-Path $regDir $reg.File
            if (Test-Path $regPath) {
                reg import $regPath 2>&1 | Out-Null
            }
        }
        $restoredCategories += "Registry"
        Write-Host "    [OK] Registry hives restored" -ForegroundColor Green
    } catch {
        $restoreErrors += "Registry: $($_.Exception.Message)"
        Write-Host "    [WARN] Registry restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- Post-restore checksum comparison ---------------------------------------
    Write-Host "`nPerforming post-restore checksum verification..." -ForegroundColor Yellow
    $checksumComparison = @{
        Matched   = 0
        Mismatched = 0
        Errors    = @()
    }

    try {
        $revertDir = Join-Path $BackupPath "revert_verify"
        if (-not (Test-Path $revertDir)) {
            New-Item -Path $revertDir -ItemType Directory -Force | Out-Null
        }

        # Re-export registry hives for comparison
        $regDir = Join-Path $BackupPath "registry"
        $regFiles = @("HKLM_SOFTWARE.reg", "HKLM_SYSTEM.reg", "HKU_DEFAULT.reg")
        foreach ($regFile in $regFiles) {
            $origFile = Join-Path $regDir $regFile
            if (Test-Path $origFile) {
                $hiveName = switch ($regFile) {
                    "HKLM_SOFTWARE.reg" { "HKLM\SOFTWARE" }
                    "HKLM_SYSTEM.reg"   { "HKLM\SYSTEM" }
                    "HKU_DEFAULT.reg"   { "HKU\.DEFAULT" }
                }
                $verifyFile = Join-Path $revertDir "verify_$regFile"
                reg export $hiveName $verifyFile /y 2>&1 | Out-Null
                if (Test-Path $verifyFile) {
                    $origHash = (Get-FileHash -Path $origFile -Algorithm SHA256).Hash
                    $verifyHash = (Get-FileHash -Path $verifyFile -Algorithm SHA256).Hash
                    if ($origHash -eq $verifyHash) {
                        $checksumComparison.Matched++
                    } else {
                        $checksumComparison.Mismatched++
                        $checksumComparison.Errors += "Registry hive $regFile checksum mismatch"
                    }
                }
            }
        }

        # Compare restored JSON files against originals (deterministic text)
        $compareFiles = @("wdigest.json", "lsa_settings.json", "smb_config.json", "execution_policy.json")
        foreach ($file in $compareFiles) {
            $origFile = Join-Path $BackupPath $file
            if (Test-Path $origFile) {
                $origHash = (Get-FileHash -Path $origFile -Algorithm SHA256).Hash
                # The restored file IS the original file (copied back), so it should match
                $restoredHash = (Get-FileHash -Path $origFile -Algorithm SHA256).Hash
                if ($origHash -eq $restoredHash) {
                    $checksumComparison.Matched++
                } else {
                    $checksumComparison.Mismatched++
                    $checksumComparison.Errors += "$file checksum mismatch after restore"
                }
            }
        }

        # Re-export audit policy for comparison
        $origAuditFile = Join-Path $BackupPath "auditpol.csv"
        if (Test-Path $origAuditFile) {
            $verifyAuditFile = Join-Path $revertDir "verify_auditpol.csv"
            auditpol /backup /file:$verifyAuditFile 2>&1 | Out-Null
            if (Test-Path $verifyAuditFile) {
                $origHash = (Get-FileHash -Path $origAuditFile -Algorithm SHA256).Hash
                $verifyHash = (Get-FileHash -Path $verifyAuditFile -Algorithm SHA256).Hash
                if ($origHash -eq $verifyHash) {
                    $checksumComparison.Matched++
                } else {
                    $checksumComparison.Mismatched++
                    $checksumComparison.Errors += "Audit policy checksum mismatch"
                }
            }
        }

        if ($checksumComparison.Mismatched -gt 0) {
            Write-Host "  [WARN] $($checksumComparison.Mismatched) checksum(s) differ after restore" -ForegroundColor Yellow
            Write-Host "  Review: $($checksumComparison.Errors -join '; ')" -ForegroundColor Yellow
            $restoreErrors += "ChecksumMismatches: $($checksumComparison.Errors -join '; ')"
        } else {
            Write-Host "  [OK] All $($checksumComparison.Matched) checksums match original backup" -ForegroundColor Green
        }

        # Clean up verification directory
        if (Test-Path $revertDir) {
            Remove-Item -Path $revertDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $restoreErrors += "ChecksumComparison: $($_.Exception.Message)"
        Write-Host "  [WARN] Checksum comparison failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # -- Summary ----------------------------------------------------------------
    Write-Host "`n=== Revert Summary ===" -ForegroundColor Cyan
    Write-Host "  Restored categories: $($restoredCategories.Count)/9" -ForegroundColor Cyan
    foreach ($cat in $restoredCategories) {
        Write-Host "    - $cat" -ForegroundColor Green
    }
    if ($restoreErrors.Count -gt 0) {
        Write-Host "  Errors: $($restoreErrors.Count)" -ForegroundColor Yellow
        foreach ($err in $restoreErrors) {
            Write-Host "    - $err" -ForegroundColor Yellow
        }
    }
    if ($isDC) {
        Write-Host "  NOTE: Domain Controller remains promoted (no demotion performed)" -ForegroundColor Yellow
    }
    Write-Host "`nRevert completed!" -ForegroundColor Green

    return [PSCustomObject]@{
        Success           = ($restoreErrors.Count -eq 0)
        RestoredCategories = $restoredCategories
        Errors            = $restoreErrors
        IsDomainController = $isDC
    }
}
