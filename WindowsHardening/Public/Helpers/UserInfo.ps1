#Requires -Version 5.1

# UserInfo.ps1 - User listing and deterministic password generation.

function Show-Users {
    [CmdletBinding()]
    param()

    Initialize-System

    try {
        $output = @()
        $isDC = $script:HardeningContext.OS.IsDomainController

        Write-Host "`n==== Enabled Users ====" -ForegroundColor Green
        $enabledUsersOutput = "==== Enabled Users ===="

        if ($isDC) {
            $enabledUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $true -and $_.ObjectClass -eq "User" }
        } else {
            $enabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        }

        $enabledUsers | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $enabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            $userSID = $user.SID

            if ($isDC) {
                $groups = Get-ADGroup -Filter * | Where-Object {
                    $groupMembers = Get-ADGroupMember -Identity $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            } else {
                $groups = Get-LocalGroup | Where-Object {
                    $groupMembers = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            }

            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $enabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $enabledUsersOutput

        Write-Host "`n==== Disabled Users ====" -ForegroundColor Red
        $disabledUsersOutput = "==== Disabled Users ===="

        if ($isDC) {
            $disabledUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $false }
        } else {
            $disabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $false }
        }

        $disabledUsers | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $disabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            $userSID = $user.SID

            if ($isDC) {
                $groups = Get-ADGroup -Filter * | Where-Object {
                    $groupMembers = Get-ADGroupMember -Identity $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            } else {
                $groups = Get-LocalGroup | Where-Object {
                    $groupMembers = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            }

            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $disabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $disabledUsersOutput

        return $output
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Show-Users: $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-WordIndex {
    param(
        [Parameter(Mandatory=$true)]
        [int]$HashValue,

        [Parameter(Mandatory=$true)]
        [int]$WordlistCount
    )
    $TARGET_MAX = $WordlistCount - 1
    if ($TARGET_MAX -lt 0) { return 0 }
    return [int][Math]::Truncate(((($TARGET_MAX) * ($HashValue - 0x0000)) / (0xFFFF - 0x0000)))
}

function New-Password {
    <#
    .SYNOPSIS
        Generates a deterministic passphrase for a user given a seed phrase and wordlist.

    .DESCRIPTION
        Hashes (seed + username) with MD5, maps each 16-bit chunk to a wordlist index,
        and concatenates -NumWords words separated by dashes, with a trailing '1'.
        The result is always the same for the same inputs, making it reproducible
        across machines without storing passwords.

    .PARAMETER Username
        The username to generate a password for.

    .PARAMETER SeedPhrase
        The shared secret seed phrase (e.g. from -SaltPhrase).

    .PARAMETER WordlistData
        Array of words loaded from wordlist.txt.

    .EXAMPLE
        $words = Get-Content .\wordlist.txt
        New-Password -Username "jsmith" -SeedPhrase "competition2025" -WordlistData $words
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [string]$SeedPhrase,

        [Parameter(Mandatory=$true)]
        [string[]]$WordlistData,

        # At most 8: each word uses 4 hex characters of the 32-character MD5 hash.
        [ValidateRange(1, 8)]
        [int]$NumWords = 5
    )

    $inputString = "$SeedPhrase$Username"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString))
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''

    $password = ""
    for ($i = 0; $i -lt ($NumWords * 4); $i += 4) {
        if ($i -ne 0) { $password += "-" }
        $hex = $hashString.Substring($i, 4)
        $dec = [Convert]::ToInt32($hex, 16)
        $index = ConvertTo-WordIndex -HashValue $dec -WordlistCount $WordlistData.Count
        $password += $WordlistData[$index]
    }
    $password + "1"
}

Set-Alias -Name Print-Users -Value Show-Users
