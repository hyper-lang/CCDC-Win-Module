function Backup-WindowsState {
    <#
    .SYNOPSIS
        Captures a point-in-time configuration snapshot of the Windows system state.

    .DESCRIPTION
        Creates a timestamped backup subfolder containing 10 categories of system
        configuration data that the hardening module can modify. Use the backup as
        a baseline before hardening so Restore-WindowsState can restore configuration
        values if needed.

        Captured categories:
          1. Registry hives       (HKLM\SOFTWARE, HKLM\SYSTEM, HKU\.DEFAULT as .reg files;
                                   security-relevant values as JSON for value-level restore)
          2. Service configs      (startup type, status, service account, binary path)
          3. Firewall             (profiles and rules as JSON; native .wfw export via netsh)
          4. Local users/groups   (accounts and group memberships)
          5. Audit policy         (auditpol /backup CSV)
          6. SMB configuration    (SMBv1/v2 enabled state, encryption settings)
          7. WDigest              (UseLogonCredential registry value)
          8. Execution policy     (current scope policy)
          9. LSA settings         (HKLM:\SYSTEM\CurrentControlSet\Control\Lsa values)
         10. SHA256 checksums     (integrity manifest of all backup files)

    .CAPABILITIES
        - Point-in-time configuration snapshot before hardening operations.
        - Checksum manifest (checksums.txt) enables tamper detection before restore.
        - Partial-success model: one failed category writes a warning but does not abort
          the remaining categories.
        - Hidden default path (C:\Windows\System32\wbem\.hb\) reduces attacker visibility.
        - Works on domain controllers and member servers (Server 2016-2022 tested).

    .LIMITATIONS
        THIS IS A CONFIGURATION SNAPSHOT, NOT A DISK IMAGE. It is NOT equivalent to a
        VM/hypervisor snapshot. The following are NOT captured and cannot be restored:

        - Filesystem contents: new files, dropped binaries, modified executables,
          WMI subscriptions, scheduled tasks, COM hijacks, DLL sideloads, or any
          filesystem-level persistence added after the backup was taken.

        - In-memory threats: injected code, fileless implants, and in-memory credentials.

        - Boot/firmware persistence: bootkits, MBR/VBR modifications, UEFI implants.

        - AD persistence (on domain controllers): ACL backdoors, AdminSDHolder abuse,
          shadow credentials, rogue CA certificates, SPN abuse, and Kerberos ticket
          material cannot be captured by a configuration export.

        - Registry .reg imports on a live system WILL FAIL (HKLM hives are locked while
          Windows runs). The .reg files are kept for offline recovery (WinPE / offline hive
          mount) only. Security-relevant values are separately captured as JSON for
          value-level restore via Restore-WindowsState.

        - User passwords: cannot be round-tripped. After a restore, account passwords
          remain at whatever they were set to during hardening.

        - If the system is already compromised when the backup is taken, the backup
          captures the attacker's configuration alongside the legitimate one.

    .PARAMETER BackupPath
        Root folder for backups. A timestamped subfolder is created on each run.
        Default: C:\Windows\System32\wbem\.hb\

    .OUTPUTS
        PSCustomObject with Success, Path, Files, Errors, and Timestamp.

    .EXAMPLE
        Backup-WindowsState
        # Creates C:\Windows\System32\wbem\.hb\<timestamp>\

    .EXAMPLE
        $result = Backup-WindowsState -BackupPath "D:\Backups"
        Restore-WindowsState -BackupPath $result.Path
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath = "C:\Windows\System32\wbem\.hb\"
    )

    $backupErrors = @()
    $backedUpFiles = @()

    try {
        # Create timestamped backup subfolder
        $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $backupDir = Join-Path $BackupPath $timestamp

        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }

        Write-Host "Creating backup at: $backupDir" -ForegroundColor Cyan

        # -- 1. Registry Hives -------------------------------------------------
        Write-Host "  [1/10] Capturing registry hives..." -ForegroundColor Gray
        try {
            $regDir = Join-Path $backupDir "registry"
            if (-not (Test-Path $regDir)) {
                New-Item -Path $regDir -ItemType Directory -Force | Out-Null
            }

            reg export "HKLM\SOFTWARE" (Join-Path $regDir "HKLM_SOFTWARE.reg") /y 2>&1 | Out-Null
            if (Test-Path (Join-Path $regDir "HKLM_SOFTWARE.reg")) { $backedUpFiles += "registry\HKLM_SOFTWARE.reg" }

            reg export "HKLM\SYSTEM" (Join-Path $regDir "HKLM_SYSTEM.reg") /y 2>&1 | Out-Null
            if (Test-Path (Join-Path $regDir "HKLM_SYSTEM.reg")) { $backedUpFiles += "registry\HKLM_SYSTEM.reg" }

            reg export "HKU\.DEFAULT" (Join-Path $regDir "HKU_DEFAULT.reg") /y 2>&1 | Out-Null
            if (Test-Path (Join-Path $regDir "HKU_DEFAULT.reg")) { $backedUpFiles += "registry\HKU_DEFAULT.reg" }

            # Also export specific security-relevant values as JSON for easy inspection
            $regValues = @{}

            # WDigest UseLogonCredential
            $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
            if ($null -ne $wdigest) {
                $regValues['WDigest_UseLogonCredential'] = $wdigest.UseLogonCredential
            }

            # UAC settings
            $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $uacProps = Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue
            if ($null -ne $uacProps) {
                $regValues['EnableLUA'] = $uacProps.EnableLUA
                $regValues['ConsentPromptBehaviorAdmin'] = $uacProps.ConsentPromptBehaviorAdmin
                $regValues['EnableInstallerDetection'] = $uacProps.EnableInstallerDetection
                $regValues['EnableSecureUIAPaths'] = $uacProps.EnableSecureUIAPaths
                $regValues['EnableVirtualization'] = $uacProps.EnableVirtualization
                $regValues['FilterAdministratorToken'] = $uacProps.FilterAdministratorToken
                $regValues['EnableUIADesktopToggle'] = $uacProps.EnableUIADesktopToggle
            }

            # NoDriveTypeAutoRun
            $noRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $noRunProps = Get-ItemProperty -Path $noRunPath -ErrorAction SilentlyContinue
            if ($null -ne $noRunProps) {
                $regValues['NoDriveTypeAutoRun'] = $noRunProps.NoDriveTypeAutoRun
            }

            $regValues | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $regDir "security_values.json") -Encoding UTF8
            if (Test-Path (Join-Path $regDir "security_values.json")) { $backedUpFiles += "registry\security_values.json" }

            Write-Host "    [OK] Registry hives captured" -ForegroundColor Green
        } catch {
            $backupErrors += "Registry: $($_.Exception.Message)"
            Write-Host "    [WARN] Registry capture partially failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 2. Service Startup Types + Accounts -------------------------------
        Write-Host "  [2/10] Capturing service configurations..." -ForegroundColor Gray
        try {
            $svcFile = Join-Path $backupDir "services.json"
            $services = Get-Service | Select-Object Name, StartType, Status
            $serviceDetails = @()
            foreach ($svc in $services) {
                $wmi = Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
                $detail = [PSCustomObject]@{
                    Name       = $svc.Name
                    StartType  = $svc.StartType
                    Status     = $svc.Status
                    StartName  = if ($wmi) { $wmi.StartName } else { $null }
                    PathName   = if ($wmi) { $wmi.PathName } else { $null }
                }
                $serviceDetails += $detail
            }
            $serviceDetails | ConvertTo-Json -Depth 5 | Out-File -FilePath $svcFile -Encoding UTF8
            $backedUpFiles += "services.json"
            Write-Host "    [OK] Service configurations captured ($($services.Count) services)" -ForegroundColor Green
        } catch {
            $backupErrors += "Services: $($_.Exception.Message)"
            Write-Host "    [WARN] Service capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 3. Firewall Profiles + Rules --------------------------------------
        Write-Host "  [3/10] Capturing firewall configuration..." -ForegroundColor Gray
        try {
            $fwDir = Join-Path $backupDir "firewall"
            if (-not (Test-Path $fwDir)) {
                New-Item -Path $fwDir -ItemType Directory -Force | Out-Null
            }

            # Profiles
            $profiles = Get-NetFirewallProfile
            $profiles | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $fwDir "profiles.json") -Encoding UTF8
            $backedUpFiles += "firewall\profiles.json"

            # Rules
            $rules = Get-NetFirewallRule | Select-Object Name, DisplayName, Direction, Action, Enabled, Profile,
                @{Name='LocalPort'; Expression={ $_ | Get-NetFirewallPortFilter | Select-Object -ExpandProperty LocalPort }},
                @{Name='Protocol'; Expression={ $_ | Get-NetFirewallPortFilter | Select-Object -ExpandProperty Protocol }}
            $rules | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $fwDir "rules.json") -Encoding UTF8
            $backedUpFiles += "firewall\rules.json"

            # Native export
            $fwExportPath = Join-Path $fwDir "firewall_policy.wfw"
            Export-FirewallConfig -Path $fwExportPath
            if (Test-Path $fwExportPath) { $backedUpFiles += "firewall\firewall_policy.wfw" }

            Write-Host "    [OK] Firewall configuration captured ($($rules.Count) rules)" -ForegroundColor Green
        } catch {
            $backupErrors += "Firewall: $($_.Exception.Message)"
            Write-Host "    [WARN] Firewall capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 4. Local Users + Groups + Memberships -----------------------------
        Write-Host "  [4/10] Capturing local user and group state..." -ForegroundColor Gray
        try {
            $usersDir = Join-Path $backupDir "users"
            if (-not (Test-Path $usersDir)) {
                New-Item -Path $usersDir -ItemType Directory -Force | Out-Null
            }

            # Local users
            $localUsers = Get-LocalUser | Select-Object Name, Enabled, SID, Description, PasswordRequired, PasswordLastSet, LastLogon
            $localUsers | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $usersDir "local_users.json") -Encoding UTF8
            $backedUpFiles += "users\local_users.json"

            # Local groups
            $localGroups = Get-LocalGroup | Select-Object Name, SID, Description
            $localGroups | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $usersDir "local_groups.json") -Encoding UTF8
            $backedUpFiles += "users\local_groups.json"

            # Group memberships
            $groupMembership = @{}
            foreach ($group in $localGroups) {
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue |
                    Select-Object Name, SID, ObjectClass, PrincipalSource
                if ($null -ne $members -and $members.Count -gt 0) {
                    $groupMembership[$group.Name] = @($members | ForEach-Object {
                        [PSCustomObject]@{
                            Name          = $_.Name
                            SID           = $_.SID
                            ObjectClass   = $_.ObjectClass
                            PrincipalSource = $_.PrincipalSource
                        }
                    })
                }
            }
            $groupMembership | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $usersDir "group_memberships.json") -Encoding UTF8
            $backedUpFiles += "users\group_memberships.json"

            Write-Host "    [OK] User/group state captured ($($localUsers.Count) users, $($localGroups.Count) groups)" -ForegroundColor Green
        } catch {
            $backupErrors += "Users/Groups: $($_.Exception.Message)"
            Write-Host "    [WARN] User/group capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 5. Auditpol Settings ----------------------------------------------
        Write-Host "  [5/10] Capturing audit policy..." -ForegroundColor Gray
        try {
            $auditFile = Join-Path $backupDir "auditpol.csv"
            auditpol /backup /file:$auditFile 2>&1 | Out-Null
            if (Test-Path $auditFile) {
                $backedUpFiles += "auditpol.csv"
                Write-Host "    [OK] Audit policy captured" -ForegroundColor Green
            } else {
                throw "auditpol export did not create file"
            }
        } catch {
            $backupErrors += "Auditpol: $($_.Exception.Message)"
            Write-Host "    [WARN] Audit policy capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 6. SMB Configuration ----------------------------------------------
        Write-Host "  [6/10] Capturing SMB configuration..." -ForegroundColor Gray
        try {
            $smbFile = Join-Path $backupDir "smb_config.json"
            $smbConfig = Get-SmbServerConfiguration
            $smbConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $smbFile -Encoding UTF8
            $backedUpFiles += "smb_config.json"
            Write-Host "    [OK] SMB configuration captured" -ForegroundColor Green
        } catch {
            $backupErrors += "SMB: $($_.Exception.Message)"
            Write-Host "    [WARN] SMB capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 7. WDigest Registry Values ----------------------------------------
        Write-Host "  [7/10] Capturing WDigest configuration..." -ForegroundColor Gray
        try {
            $wdigestFile = Join-Path $backupDir "wdigest.json"
            $wdigestValues = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
            if ($null -ne $wdigestValues) {
                $wdigestData = @{
                    UseLogonCredential = $wdigestValues.UseLogonCredential
                }
            } else {
                $wdigestData = @{ UseLogonCredential = $null }
            }
            $wdigestData | ConvertTo-Json -Depth 5 | Out-File -FilePath $wdigestFile -Encoding UTF8
            $backedUpFiles += "wdigest.json"
            Write-Host "    [OK] WDigest configuration captured" -ForegroundColor Green
        } catch {
            $backupErrors += "WDigest: $($_.Exception.Message)"
            Write-Host "    [WARN] WDigest capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 8. Execution Policy -----------------------------------------------
        Write-Host "  [8/10] Capturing execution policy..." -ForegroundColor Gray
        try {
            $execFile = Join-Path $backupDir "execution_policy.json"
            $currentPolicy = Get-ExecutionPolicy
            @{
                ExecutionPolicy = $currentPolicy
            } | ConvertTo-Json | Out-File -FilePath $execFile -Encoding UTF8
            $backedUpFiles += "execution_policy.json"
            Write-Host "    [OK] Execution policy captured: $currentPolicy" -ForegroundColor Green
        } catch {
            $backupErrors += "ExecutionPolicy: $($_.Exception.Message)"
            Write-Host "    [WARN] Execution policy capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 9. LSA Settings --------------------------------------------------
        Write-Host "  [9/10] Capturing LSA settings..." -ForegroundColor Gray
        try {
            $lsaFile = Join-Path $backupDir "lsa_settings.json"
            $lsaValues = Get-LSARegistryValues
            $lsaValues | ConvertTo-Json -Depth 10 | Out-File -FilePath $lsaFile -Encoding UTF8
            $backedUpFiles += "lsa_settings.json"
            Write-Host "    [OK] LSA settings captured" -ForegroundColor Green
        } catch {
            $backupErrors += "LSA: $($_.Exception.Message)"
            Write-Host "    [WARN] LSA capture failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- 10. SHA256 Checksums ----------------------------------------------
        Write-Host "  [10/10] Generating checksums..." -ForegroundColor Gray
        try {
            $checksumFile = Join-Path $backupDir "checksums.txt"
            $checksumEntries = @()
            foreach ($file in $backedUpFiles) {
                $fullPath = Join-Path $backupDir $file
                if (Test-Path $fullPath) {
                    $hash = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash
                    $checksumEntries += "$hash  $file"
                }
            }
            $checksumEntries | Out-File -FilePath $checksumFile -Encoding UTF8
            $backedUpFiles += "checksums.txt"
            Write-Host "    [OK] Checksums generated ($($checksumEntries.Count) files)" -ForegroundColor Green
        } catch {
            $backupErrors += "Checksums: $($_.Exception.Message)"
            Write-Host "    [WARN] Checksum generation failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # -- Summary -----------------------------------------------------------
        Write-Host "`nBackup completed successfully!" -ForegroundColor Green
        Write-Host "  Location: $backupDir" -ForegroundColor Cyan
        Write-Host "  Files: $($backedUpFiles.Count)" -ForegroundColor Cyan
        if ($backupErrors.Count -gt 0) {
            Write-Host "  Warnings: $($backupErrors.Count)" -ForegroundColor Yellow
            foreach ($err in $backupErrors) {
                Write-Host "    - $err" -ForegroundColor Yellow
            }
        }

        # Return structured result
        return [PSCustomObject]@{
            Success  = $true
            Path     = $backupDir
            Files    = $backedUpFiles
            Errors   = $backupErrors
            Timestamp = $timestamp
        }

    } catch {
        Write-Host "Backup failed: $($_.Exception.Message)" -ForegroundColor Red
        return [PSCustomObject]@{
            Success  = $false
            Path     = $null
            Files    = @()
            Errors   = @($_.Exception.Message)
            Timestamp = $null
        }
    }
}
