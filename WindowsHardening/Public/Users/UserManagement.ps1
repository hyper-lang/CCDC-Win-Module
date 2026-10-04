#Requires -Version 5.1

# UserManagement.ps1 - Password changes, user creation, and initial competition-account setup.

function New-ADUserAccount {
    param(
        [string]$Name,
        [string]$SamAccountName
    )
    # Create the AD user under the domain's official Users container. New-ADUser with
    # only -Name/-SamAccountName (no -Path) on a freshly promoted forest root can place
    # the object where it is not resolvable via -Identity, so always target the container.
    $path = $null
    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
        try {
            $path = (Get-ADDomain -ErrorAction Stop).UsersContainer
        } catch {
            try { $path = "CN=Users,$((Get-ADRootDSE -ErrorAction Stop).defaultNamingContext)" } catch { $path = $null }
        }
    }
    if ($path) {
        New-ADUser -Name $Name -SamAccountName $SamAccountName -Path $path
    } else {
        New-ADUser -Name $Name -SamAccountName $SamAccountName
    }
}

function Set-UserPassword {
    <#
    .SYNOPSIS
        Sets a local or AD account's password; optionally adds the account to the admin group.
    .DESCRIPTION
        The password comes from -Password, or is derived from -SaltPhrase + -WordlistData
        (Zulu), or is typed at a prompt. Throws if the account does not exist, or if a
        given/derived password cannot be set, so callers can count the failure. Only a typed
        password is re-prompted after a failure (e.g. complexity rules); an empty entry gives up.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [string]$PasswordPrompt,

        [string]$Password,

        [string[]]$WordlistData,

        [string]$SaltPhrase,

        [switch]$AddToAdmins
    )

    $isDC = (Get-OperatingSystemInfo).IsDomainController

    # Check first: setting a password on a missing account can never succeed.
    $exists = if ($isDC) {
        [bool](Get-ADUser -Filter "SamAccountName -eq '$Username'")
    } else {
        [bool](Get-LocalUser -Name $Username -ErrorAction Ignore)
    }
    if (-not $exists) {
        throw "User '$Username' does not exist"
    }

    if (-not $Password -and $SaltPhrase -and $WordlistData) {
        # Non-interactive: derive a deterministic password from the salt phrase. Required
        # over WinRM, where Read-Host is unavailable.
        $Password = New-Password -Username $Username -SeedPhrase $SaltPhrase -WordlistData $WordlistData
    }
    $prompted = -not $Password

    while ($true) {
        if ($prompted) {
            $Password = Read-SecretInput $PasswordPrompt
            if (-not $Password) {
                throw "No password entered for '$Username'"
            }
            if ($Password -ne (Read-SecretInput "Confirm password: ")) {
                Write-Status -Level Warning "Passwords do not match. Try again (Enter to give up)."
                continue
            }
        }

        $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
        try {
            if ($isDC) {
                Set-ADAccountPassword -Identity $Username -Reset -NewPassword $securePassword -ErrorAction Stop
            } else {
                Set-LocalUser -Name $Username -Password $securePassword -ErrorAction Stop
            }
            break
        } catch {
            if (-not $prompted) {
                throw "Could not set password for '$Username': $($_.Exception.Message)"
            }
            Write-Status -Level Error "Could not set password for ${Username}: $($_.Exception.Message)"
            Write-Status -Level Warning "Try a different password (likely complexity requirements), or press Enter to give up."
        }
    }

    if ($AddToAdmins) {
        # Already being a member is fine; anything else is reported but does not undo the password.
        try {
            if ($isDC) {
                Add-ADGroupMember -Identity "Domain Admins" -Members $Username -ErrorAction Stop
            } else {
                Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
            }
        } catch {
            if ($_.Exception.Message -notmatch 'already a member|member of the group') {
                Write-Status -Level Warning "Could not add $Username to the admin group: $($_.Exception.Message)"
            }
        }
    }
}

function Set-CompetitionInteractiveLogonRights {
    <#
    .SYNOPSIS
        Allows specified AD users to sign in interactively at a domain controller.
    .DESCRIPTION
        User-rights assignments are stored as SIDs, not account names.  Export the
        current USER_RIGHTS policy, add the requested account SIDs to
        SeInteractiveLogonRight, remove them from SeDenyInteractiveLogonRight, and
        import the policy while preserving unrelated entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Usernames
    )

    $sids = foreach ($username in $Usernames) {
        $adUser = Get-ADUser -Identity $username -Properties SID -ErrorAction Stop
        "*$($adUser.SID.Value)"
    }

    $tempRoot = [System.IO.Path]::GetTempPath()
    $exportPath = Join-Path $tempRoot ("WindowsHardening-{0}.inf" -f ([guid]::NewGuid().ToString('N')))
    $databasePath = Join-Path $tempRoot ("WindowsHardening-{0}.sdb" -f ([guid]::NewGuid().ToString('N')))

    try {
        & secedit.exe /export /cfg $exportPath /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exportPath)) {
            throw "secedit could not export the current user-rights policy (exit code $LASTEXITCODE)"
        }

        $policy = Get-Content -LiteralPath $exportPath -Raw -ErrorAction Stop
        if ($policy -notmatch '(?im)^\[Privilege Rights\]\s*$') {
            throw "The exported security policy does not contain a [Privilege Rights] section"
        }

        function Update-PrivilegeRight {
            param(
                [string]$Content,
                [string]$Privilege,
                [string[]]$AddSids,
                [string[]]$RemoveSids
            )

            $linePattern = '(?im)^' + [regex]::Escape($Privilege) + '\s*=\s*(?<value>[^\r\n]*)$'
            $match = [regex]::Match($Content, $linePattern)
            $entries = @()
            if ($match.Success -and $match.Groups['value'].Value.Trim()) {
                $entries = @($match.Groups['value'].Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }

            foreach ($sid in $RemoveSids) {
                $entries = @($entries | Where-Object { $_ -ne $sid })
            }
            foreach ($sid in $AddSids) {
                if ($entries -notcontains $sid) {
                    $entries += $sid
                }
            }

            $replacement = "$Privilege = $($entries -join ',')"
            if ($match.Success) {
                return [regex]::Replace($Content, $linePattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacement })
            }

            return [regex]::Replace(
                $Content,
                '(?im)^(\[Privilege Rights\]\s*)$',
                [System.Text.RegularExpressions.MatchEvaluator]{ param($m) "$($m.Groups[1].Value)`r`n$replacement" }
            )
        }

        $policy = Update-PrivilegeRight -Content $policy -Privilege 'SeDenyInteractiveLogonRight' -RemoveSids $sids -AddSids @()
        $policy = Update-PrivilegeRight -Content $policy -Privilege 'SeInteractiveLogonRight' -AddSids $sids -RemoveSids @()
        Set-Content -LiteralPath $exportPath -Value $policy -Encoding Unicode -Force -ErrorAction Stop

        & secedit.exe /configure /db $databasePath /cfg $exportPath /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "secedit could not apply the updated user-rights policy (exit code $LASTEXITCODE)"
        }

        Write-Status -Level Success "Interactive console logon allowed for $($Usernames -join ', ')" `
            -LogMessage "Granted SeInteractiveLogonRight to $($sids -join ', '); removed those SIDs from SeDenyInteractiveLogonRight"
    } finally {
        Remove-Item -LiteralPath $exportPath, $databasePath -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-CompetitionUsers {
    <#
    .SYNOPSIS
        Resets the Administrator password and creates the competition accounts.
    .DESCRIPTION
        DC: Administrator, plus domain users ccdcuser2 (standard) and ccdcuser3 (Domain Admin).
        Otherwise: Administrator, plus local users ccdcuser1 (Administrators) and ccdcuser2.
        Each account is handled on its own, so one failure does not stop the others.
        Returns the number of accounts that failed.
    #>
    [CmdletBinding()]
    param(
        [string[]]$WordlistData,

        # When given, account passwords are derived from it instead of prompted for.
        [string]$SaltPhrase
    )

    $isDC = (Get-OperatingSystemInfo).IsDomainController
    $failed = 0

    $passwordArgs = @{ WordlistData = $WordlistData; SaltPhrase = $SaltPhrase }

    Write-Status "Changing Administrator password"
    try {
        Set-UserPassword -Username "Administrator" -PasswordPrompt "Enter new password for Administrator: " @passwordArgs
    } catch {
        $failed++
        Write-Status -Level Error "Administrator password NOT changed: $($_.Exception.Message)"
    }

    if ($isDC) {
        # ccdcuser2 (standard) and ccdcuser3 (Domain Admin) in AD; ccdcuser1 is local-only.
        # Lookups use -Filter: Get-ADUser -Identity throws for a missing user even with
        # -ErrorAction SilentlyContinue. New-ADUser without a password creates a disabled
        # account, so each user is enabled once its password is set.
        Write-Status "Setting up domain users ccdcuser2 and ccdcuser3"
        foreach ($u in @("ccdcuser2", "ccdcuser3")) {
            try {
                if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'")) {
                    New-ADUserAccount -Name $u -SamAccountName $u
                }
                Set-UserPassword -Username $u -PasswordPrompt "Enter password for ${u}: " -AddToAdmins:($u -eq "ccdcuser3") @passwordArgs
                Enable-ADAccount -Identity $u -ErrorAction Stop
                Write-Status -Level Success "$u ready"
            } catch {
                $failed++
                Write-Status -Level Warning "Domain user '$u' not set up: $($_.Exception.Message)" -LogMessage "Domain user '$u' setup failed: $($_.Exception.Message)"
            }
        }

        try {
            Set-CompetitionInteractiveLogonRights -Usernames @("ccdcuser2", "ccdcuser3")
        } catch {
            $failed++
            Write-Status -Level Warning "Could not grant console sign-in rights to ccdcuser2/ccdcuser3: $($_.Exception.Message)" `
                -LogMessage "Interactive logon rights setup failed: $($_.Exception.Message)"
        }
    } else {
        Write-Status "Setting up local users ccdcuser1 and ccdcuser2"
        foreach ($u in @("ccdcuser1", "ccdcuser2")) {
            try {
                if (-not (Get-LocalUser -Name $u -ErrorAction Ignore)) {
                    New-LocalUser -Name $u -NoPassword -ErrorAction Stop | Out-Null
                }
                Set-UserPassword -Username $u -PasswordPrompt "Enter password for ${u}: " -AddToAdmins:($u -eq "ccdcuser1") @passwordArgs
                Write-Status -Level Success "$u ready"
            } catch {
                $failed++
                Write-Status -Level Warning "Local user '$u' not set up: $($_.Exception.Message)" -LogMessage "Local user '$u' setup failed: $($_.Exception.Message)"
            }
        }
    }

    return $failed
}
