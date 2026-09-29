function Set-ZuluPassword {
    [CmdletBinding()]
    param(
        [Alias("h")][switch]$Help,
        [Alias("i")][switch]$Initial,
        [string]$User,
        # -U (and -u: aliases ignore case) mean -UsersFile, not -User.
        [Alias("U")][string]$UsersFile,
        [Alias("g")][switch]$GenerateOnly,
        [Alias("p")][string]$PCRFile,
        [Alias("s", "Seed")][string]$SaltPhrase,

        [Parameter(HelpMessage = "If we need to download the wordlist, this is the URL to get it from")]
        [Alias("url")]
        [string]$WordlistUrl = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/wordlist.txt",

        # Where zulu.log and users_zulu.csv are written. Default: the module's log directory.
        [string]$OutputDirectory
    )

    process {
        # -Initial creates and resets accounts, so it cannot run as a dry run.
        if ($Initial -and $GenerateOnly) {
            throw "-Initial and -GenerateOnly cannot be used together (-Initial changes account passwords)."
        }

        # Script configuration
        if (-not $OutputDirectory) {
            $OutputDirectory = if ($script:HardeningContext.LogPath) { $script:HardeningContext.LogPath } else { $script:DefaultLogPath }
        }
        if (-not $GenerateOnly -and -not (Test-Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }
        $ExportUsersFile = Join-Path $OutputDirectory "users_zulu.csv"
        $LogFile = Join-Path $OutputDirectory "zulu.log"
        $WordlistFile = Join-Path $script:DataPath "wordlist.txt"
        $ExcludedUsers = @("Administrator", "ccdcuser1", "ccdcuser2", "ccdcuser3")

        if ($Help) {
            Write-Host "Usage: Set-ZuluPassword [options]" -ForegroundColor Green
            Write-Host "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users."
            Write-Host "`nOptions:" -ForegroundColor Yellow
            @(
                "  -Help, -h          Show this help message",
                "  -Initial, -i       Perform initial setup (change Administrator password and create ccdcuser1/2)",
                "  -User              Change password for a single user",
                "  -UsersFile, -U     Change passwords for newline-separated users in a file (-u also means this)",
                "  -GenerateOnly, -g  Generate/print passwords only, do not change them (not with -Initial)",
                "  -PCRFile, -p       Output generated passwords as 'username,password' to a PCR (CSV) file",
                "  -SaltPhrase, -s    Salt phrase (non-interactive; skips prompt). Alias: -Seed",
                "  -url <url>         The url to the wordlist (used only if Data\wordlist.txt is missing)",
                "  -OutputDirectory   Where zulu.log / users_zulu.csv go (default: log directory)"
            ) | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
            return
        }

        Write-Host "Starting Zulu Password Generator Script..." -ForegroundColor Green
        Write-ZuluLog -Message "Script started at $(Get-Date)" -LogFile $LogFile -GenerateOnly:$GenerateOnly
        Write-Host "The default behavior is to change passwords for all users except: $($ExcludedUsers -join ', ')."

        # Generating passwords needs no admin rights; changing them does.
        if (-not $GenerateOnly) {
            Test-Prerequisites
        }

        $IsDomainController = (Get-OperatingSystemInfo).IsDomainController
        if ($IsDomainController) {
            Write-Host "Domain Controller detected - AD password operations will be used." -ForegroundColor Green
        }

        Write-Host "`nPreparing to generate passwords..."

        # Salt phrase: -SaltPhrase if given (non-interactive), otherwise prompt.
        $seedFromPrompt = $false
        if ($SaltPhrase) {
            if ($SaltPhrase.Length -lt 8) {
                Write-Host "Salt phrase must be at least 8 characters long." -ForegroundColor Red
                throw "Salt phrase must be at least 8 characters long."
            }
            $seedPhrase = $SaltPhrase
        } else {
            $seedFromPrompt = $true
            while ($true) {
                $seedPhrase = Read-SecretInput "Enter seed phrase: "
                $confirmSeedPhrase = Read-SecretInput "Confirm seed phrase: "

                if ($seedPhrase -ne $confirmSeedPhrase) {
                    Write-Host "Seed phrases do not match. Please retry." -ForegroundColor Yellow
                    continue
                }
                if ($seedPhrase.Length -lt 8) {
                    Write-Host "Seed phrase must be at least 8 characters long. Please retry." -ForegroundColor Yellow
                    continue
                }
                break
            }
        }

        if (-not (Test-Path $WordlistFile)) {
            Write-Host "Downloading wordlist file..." -ForegroundColor Green
            if (-not (Get-FileFromUrl -Url $WordlistUrl -OutputPath $WordlistFile)) {
                throw "Failed to download wordlist from $WordlistUrl"
            }
        }
        $wordlistData = @(Get-Content $WordlistFile)

        if ($Initial) {
            Write-Host "Performing initial user setup..." -ForegroundColor Green
            # A salt given via -SaltPhrase also derives the initial account passwords (needed for
            # non-interactive runs, where Read-Host fails). A typed seed means someone is at the
            # keyboard, so those passwords are entered by hand instead.
            if ($seedFromPrompt) {
                Initialize-CompetitionUsers -WordlistData $wordlistData
            } else {
                Initialize-CompetitionUsers -WordlistData $wordlistData -SaltPhrase $seedPhrase
            }
            Set-OperationStatus "Add Competition Users" "Executed successfully"
        }

        $rawUsers = if ($User) { @($User) }
                    elseif ($UsersFile) {
                        if (-not (Test-Path $UsersFile)) { Write-Host "Users file '$UsersFile' not found." -ForegroundColor Red; throw "Users file not found: $UsersFile" }
                        Get-Content $UsersFile
                    }
                    elseif ($IsDomainController) {
                        Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.Enabled } | Select-Object -ExpandProperty SamAccountName
                    }
                    else {
                        Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name
                    }

        $users = $rawUsers | Where-Object { $_ -notin $ExcludedUsers }

        Write-Host "Generating passwords for $($users.Count) users..." -ForegroundColor Green

        $failedUsers = 0

        if (-not $GenerateOnly) {
            Remove-Item $ExportUsersFile -ErrorAction Ignore
            New-Item -ItemType File -Path $ExportUsersFile -Force | Out-Null
        }

        foreach ($username in $users) {
            $password = New-Password -Username $username -SeedPhrase $seedPhrase -WordlistData $wordlistData

            if (-not $GenerateOnly) {
                Write-Host "Changing password for user $username..."
                try {
                    Set-UserPassword -Username $username -Password $password
                    if ($IsDomainController) {
                        Write-Host "Successfully changed AD password for ${username}." -ForegroundColor Green
                        Write-ZuluLog -Message "Successfully changed AD password for ${username}." -LogFile $LogFile -GenerateOnly:$GenerateOnly
                    } else {
                        Write-Host "Successfully changed password for ${username}." -ForegroundColor Green
                        Write-ZuluLog -Message "Successfully changed password for ${username}." -LogFile $LogFile -GenerateOnly:$GenerateOnly
                    }
                    Add-Content -Path $ExportUsersFile -Value $username
                } catch {
                    $failedUsers++
                    Write-Host "Failed to change password for ${username}. $($_.Exception.Message)" -ForegroundColor Red
                    Write-ZuluLog -Message "Failed to change password for ${username}.: $($_.Exception.Message)" -LogFile $LogFile -GenerateOnly:$GenerateOnly
                }
            } elseif (-not $PCRFile) {
                Write-Host "Generated password for user '${username}': ${password}"
            }

            if ($PCRFile) {
                Add-Content -Path $PCRFile -Value "${username},${password}"
            }
        }

        if ($GenerateOnly) {
            Set-OperationStatus "Change Passwords" "Generated only (no changes)"
        } elseif ($failedUsers -gt 0) {
            Set-OperationStatus "Change Passwords" "Failed for $failedUsers of $(@($users).Count) user(s)"
        } else {
            Set-OperationStatus "Change Passwords" "Executed successfully"
        }

        Write-Host "`nDone!" -ForegroundColor Green
        Write-Host "PLEASE REMEMBER TO CHANGE THE ADMINISTRATOR PASSWORD IF NOT DONE EARLIER." -ForegroundColor Yellow
    }
}

function Write-ZuluLog {
    param(
        [string]$Message,
        [string]$LogFile,
        [switch]$GenerateOnly
    )
    if (-not $GenerateOnly -and $LogFile) {
        Add-Content -Path $LogFile -Value $Message
    }
}

Set-Alias -Name New-Zulu-Integration -Value Set-ZuluPassword
Set-Alias -Name New-ZuluIntegration -Value Set-ZuluPassword
