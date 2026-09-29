function Remove-RDPUsers {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Remove RDP Users" -ScriptBlock {
        Write-Host "Removing all users from Remote Desktop Users group..." -ForegroundColor Cyan
        $ExclusionList = @("ccdcuser1", "ccdcuser2")
        $isDC = $script:HardeningContext.OS.IsDomainController

        try {
            if ($isDC) {
                $rdpGroupMembers = Get-ADGroupMember -Identity "Remote Desktop Users" -ErrorAction SilentlyContinue
            } else {
                $rdpGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
            }

            if ($null -eq $rdpGroupMembers -or $rdpGroupMembers.Count -eq 0) {
                Write-Host "  [INFO] Remote Desktop Users group is already empty" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Remote Desktop Users group is already empty"
            } else {
                $removedCount = 0
                foreach ($member in $rdpGroupMembers) {
                    try {
                        if ($isDC) {
                            $username = $member.SAMAccountName
                        } else {
                            $username = $member.Name.Split('\')[-1]
                        }

                        if ($ExclusionList -contains $username) {
                            Write-Host "  [SKIP] Skipping $username (Protected Account)" -ForegroundColor Magenta
                            Write-Log -Level "INFO" -Message "Skipped removal of $username from RDP group"
                            continue
                        }

                        if ($isDC) {
                            Remove-ADGroupMember -Identity "Remote Desktop Users" -Members $username -Confirm:$false -ErrorAction Stop
                        } else {
                            Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $member -Confirm:$false -ErrorAction Stop
                        }

                        Write-Host "  [SUCCESS] Removed $username from Remote Desktop Users group" -ForegroundColor Green
                        Write-Log -Level "SUCCESS" -Message "Removed $username from Remote Desktop Users group"
                        $removedCount++
                    } catch {
                        $displayName = if ($isDC) { $member.SAMAccountName } else { $member.Name }
                        Write-Host "  [WARNING] Could not remove $displayName from Remote Desktop Users group: $($_.Exception.Message)" -ForegroundColor Yellow
                        Write-Log -Level "WARNING" -Message "Could not remove $displayName from Remote Desktop Users group: $($_.Exception.Message)"
                    }
                }
                Write-Host "  [INFO] Removed $removedCount user(s) from Remote Desktop Users group" -ForegroundColor Cyan
            }

            Write-Host "RDP users removed successfully - Remote Desktop Users group has been reset" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "RDP users removal completed - Remote Desktop Users group reset"
        } catch {
            Write-Host "  [ERROR] Failed to remove RDP users: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to remove RDP users: $($_.Exception.Message)"
            throw
        }
    }
}
