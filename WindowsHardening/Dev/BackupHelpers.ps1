#Requires -Version 5.1

# BackupHelpers.ps1 - Registry snapshot/restore helpers for Backup-WindowsState and
# Restore-WindowsState.

function Get-LSARegistryValues {
    $lsaPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    )
    $values = @{}
    foreach ($lsaPath in $lsaPaths) {
        $props = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            $values[$lsaPath] = @{}
            $props.PSObject.Properties | Where-Object {
                $_.Name -notlike 'PS*' -and $_.Name -ne 'PSParentPath' -and
                $_.Name -ne 'PSChildName' -and $_.Name -ne 'PSDrive' -and
                $_.Name -ne 'PSProvider'
            } | ForEach-Object {
                $values[$lsaPath][$_.Name] = $_.Value
            }
        }
    }
    return $values
}

function Restore-LSAValues {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Values
    )
    foreach ($path in $Values.Keys) {
        foreach ($name in $Values[$path].Keys) {
            $value = $Values[$path][$name]
            $existing = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction Stop
            } else {
                New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
        }
    }
}

function Restore-RegistrySecurityValues {
    <#
    .SYNOPSIS
        Restores security-relevant registry VALUES captured by Backup-TargetState.
    .DESCRIPTION
        Applies the UAC (Policies\System) and NoDriveTypeAutoRun (Explorer)
        values from registry\security_values.json. Value-level restore is the
        only registry operation that round-trips on a LIVE system - full hive
        .reg imports are impossible while the SYSTEM/SOFTWARE hives are locked
        in use, so those are archived for offline/forensic restore only.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Values
    )
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    foreach ($name in @(
        'EnableLUA', 'ConsentPromptBehaviorAdmin', 'EnableInstallerDetection',
        'EnableSecureUIAPaths', 'EnableVirtualization', 'FilterAdministratorToken',
        'EnableUIADesktopToggle')) {
        $value = $null
        try { $value = $Values.$name } catch { $value = $null }
        if ($null -ne $value) {
            Set-ItemProperty -Path $uacPath -Name $name -Value $value -ErrorAction Stop
        }
    }
    $noRun = $null
    try { $noRun = $Values.NoDriveTypeAutoRun } catch { $noRun = $null }
    if ($null -ne $noRun) {
        $expPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        Set-ItemProperty -Path $expPath -Name 'NoDriveTypeAutoRun' -Value $noRun -ErrorAction Stop
    }
}
