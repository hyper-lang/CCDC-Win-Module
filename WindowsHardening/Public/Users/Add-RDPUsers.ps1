function Add-RDPUsers {
    [CmdletBinding()]
    param(
        [string[]]$Users,
        [switch]$Force
    )

    Invoke-HardeningOperation -OperationName 'Add RDP Users' -ScriptBlock {
        Write-Banner "Add Users to Remote Desktop Users Group" -Style Inline

        $isDC = $script:HardeningContext.OS.IsDomainController
        $usernames = @()

        if ($Users -and $Users.Count -gt 0) {
            $usernames = $Users
        } elseif ($Force) {
            Write-Host "  [INFO] -Force specified with no users; nothing to add." -ForegroundColor Yellow
            return
        } else {
            $userCount = 0
            while ($true) {
                try {
                    $userCountInput = Read-Host "Enter the number of users you wish to add to the Remote Desktop Users group"
                    $userCount = [int]$userCountInput
                    if ($userCount -gt 0) {
                        break
                    } else {
                        Write-Host "  [ERROR] Please enter a positive number greater than 0." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "  [ERROR] Invalid input. Please enter a valid number." -ForegroundColor Red
                }
            }

            Write-Host "`nYou will now be prompted to enter $userCount username(s)." -ForegroundColor Yellow
            Write-Host ""

            for ($i = 1; $i -le $userCount; $i++) {
                $username = Read-Host "Enter username #$i"
                $usernames += $username
            }
        }

        $successCount = 0
        $failedCount = 0

        foreach ($username in $usernames) {
            if ([string]::IsNullOrWhiteSpace($username)) {
                Write-Host "  [WARNING] Username was empty, skipping..." -ForegroundColor Yellow
                $failedCount++
                continue
            }

            try {
                if ($isDC) {
                    Add-ADGroupMember -Identity 'Remote Desktop Users' -Members $username -ErrorAction Stop
                } else {
                    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $username -ErrorAction Stop
                }
                Write-Host "  [SUCCESS] Added user '$username' to Remote Desktop Users group" -ForegroundColor Green
                Write-Log -Level 'SUCCESS' -Message "Added user '$username' to Remote Desktop Users group"
                $successCount++
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Host "  [ERROR] Could not add user '$username' to Remote Desktop Users group: $errorMessage" -ForegroundColor Red
                Write-Log -Level 'ERROR' -Message "Could not add user '$username' to Remote Desktop Users group: $errorMessage"
                $failedCount++

                if ($errorMessage -like '*not found*' -or $errorMessage -like '*does not exist*') {
                    Write-Host "    [INFO] The user '$username' does not exist on the local system or domain." -ForegroundColor Yellow
                } elseif ($errorMessage -like '*already*' -or $errorMessage -like '*member*') {
                    Write-Host "    [INFO] The user '$username' is already a member of the Remote Desktop Users group." -ForegroundColor Yellow
                }
            }
        }

        Write-Banner "Summary" -Style Inline
        Write-Host "  Successfully added: $successCount user(s)" -ForegroundColor Green
        if ($failedCount -gt 0) {
            Write-Host "  Failed to add: $failedCount user(s)" -ForegroundColor Red
        }
        Write-Host "`nRDP user addition process completed." -ForegroundColor Green
        Write-Log -Level 'SUCCESS' -Message "Add RDP Users completed: $successCount succeeded, $failedCount failed"
    }
}
