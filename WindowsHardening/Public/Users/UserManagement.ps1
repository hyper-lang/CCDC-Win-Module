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

    if (-not $Password) {
        if ($SaltPhrase -and $WordlistData) {
            # Non-interactive: derive a deterministic password from the salt phrase. Required
            # over WinRM, where Read-Host is unavailable.
            $Password = New-Password -Username $Username -SeedPhrase $SaltPhrase -WordlistData $WordlistData
        } else {
            $Password = Read-SecretInput $PasswordPrompt
            $confirmPassword = Read-SecretInput "Confirm password: "
            if ($Password -ne $confirmPassword) {
                Write-Host "Passwords do not match." -ForegroundColor Red
                Set-UserPassword -Username $Username -PasswordPrompt $PasswordPrompt -AddToAdmins:$AddToAdmins
                return
            }
        }
    }

    $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
    try {
        if ($isDC) {
            Set-ADAccountPassword -Identity $Username -Reset -NewPassword $securePassword -ErrorAction Stop
            if ($AddToAdmins) { Add-ADGroupMember -Identity "Domain Admins" -Members $Username -ErrorAction SilentlyContinue }
        } else {
            Get-LocalUser -Name $Username | Set-LocalUser -Password $securePassword -ErrorAction Stop
            if ($AddToAdmins) { Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue }
        }
    } catch {
        Write-Host "Error setting password for ${Username}: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please try a different password (likely complexity requirements)." -ForegroundColor Yellow
        Set-UserPassword -Username $Username -PasswordPrompt $PasswordPrompt -Password $null -AddToAdmins:$AddToAdmins
    }
}

function Initialize-CompetitionUsers {
    [CmdletBinding()]
    param(
        [string[]]$WordlistData,

        # When given, account passwords are derived from it instead of prompted for.
        [string]$SaltPhrase
    )

    $isDC = (Get-OperatingSystemInfo).IsDomainController

    if ($isDC) {
        # DC path: change Administrator password + create ccdcuser2 (standard) and
        # ccdcuser3 (Domain Admin) in AD. ccdcuser1 is local-only and is not created here.
        Write-Host "Changing Administrator password..." -ForegroundColor Green
        Set-UserPassword -Username "Administrator" -PasswordPrompt "Enter new password for Administrator: " -WordlistData $WordlistData -SaltPhrase $SaltPhrase

        # Lookups use -Filter: Get-ADUser -Identity throws for a missing user even with
        # -ErrorAction SilentlyContinue. New-ADUser without a password creates a disabled
        # account, so each user is enabled once its password is set.
        Write-Host "`nCreating domain users ccdcuser2 and ccdcuser3..."
        foreach ($u in @("ccdcuser2", "ccdcuser3")) {
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'")) {
                New-ADUserAccount -Name $u -SamAccountName $u
            }
        }

        Write-Host "`nSetting passwords for CCDC domain users..."
        Set-UserPassword -Username "ccdcuser2" -PasswordPrompt "Enter password for ccdcuser2: " -WordlistData $WordlistData -SaltPhrase $SaltPhrase
        Enable-ADAccount -Identity "ccdcuser2"
        Set-UserPassword -Username "ccdcuser3" -PasswordPrompt "Enter password for ccdcuser3: " -AddToAdmins -WordlistData $WordlistData -SaltPhrase $SaltPhrase
        Enable-ADAccount -Identity "ccdcuser3"
    } else {
        # Local path: change Administrator password + create ccdcuser1/2
        Write-Host "Changing Administrator password..." -ForegroundColor Green
        Set-UserPassword -Username "Administrator" -PasswordPrompt "Enter new password for Administrator: " -WordlistData $WordlistData -SaltPhrase $SaltPhrase

        Write-Host "`nCreating ccdcuser1 and ccdcuser2..."
        @("ccdcuser1", "ccdcuser2") | ForEach-Object {
            if (-not (Get-LocalUser -Name $_ -ErrorAction Ignore)) {
                New-LocalUser -Name $_ -NoPassword
            }
        }
        Write-Host "`nSetting passwords for CCDC users..."
        Set-UserPassword -Username "ccdcuser1" -PasswordPrompt "Enter password for ccdcuser1: " -AddToAdmins -WordlistData $WordlistData -SaltPhrase $SaltPhrase
        Set-UserPassword -Username "ccdcuser2" -PasswordPrompt "Enter password for ccdcuser2: " -WordlistData $WordlistData -SaltPhrase $SaltPhrase
    }
}
