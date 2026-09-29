function Remove-AdminUsers {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Remove Admin Users" -ScriptBlock {
        $isDC = $script:HardeningContext.OS.IsDomainController

        if ($isDC) {
            Write-Host "Cleaning administrator groups on the domain (Domain Admins, Enterprise Admins, Administrators)..." -ForegroundColor Cyan
            Write-Host "Please go back and add users that need access per the competition scenario" -ForegroundColor Cyan

            $ExclusionList = @("Administrator", "ccdcuser3")

            $adminGroupList = @("Domain Admins", "Enterprise Admins", "Administrators")
            foreach ($groupName in $adminGroupList) {
                try {
                    $adminMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue

                    if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
                        Write-Host "  [INFO] ${GroupName} group is empty (Unexpected)" -ForegroundColor Yellow
                        Write-Log -Level "INFO" -Message "${GroupName} group is already empty"
                    } else {
                        $removedCount = 0
                        foreach ($member in $adminMembers) {
                            try {
                                $username = $member.SAMAccountName

                                if ($ExclusionList -contains $username) {
                                    Write-Host "  [SKIP] Skipping ${username} (Protected Admin)" -ForegroundColor Magenta
                                    Write-Log -Level "INFO" -Message "Skipped removal of ${username} from ${GroupName} group"
                                    continue
                                }

                                Remove-ADGroupMember -Identity $GroupName -Members $username -Confirm:$false -ErrorAction Stop

                                Write-Host "  [SUCCESS] Removed ${username} from ${GroupName}" -ForegroundColor Green
                                Write-Log -Level "SUCCESS" -Message "Removed ${username} from ${GroupName}"
                                $removedCount++
                            } catch {
                                $msg = $_.Exception.Message
                                Write-Host "  [WARNING] Could not remove $($member.Name): $msg" -ForegroundColor Yellow
                                Write-Log -Level "WARNING" -Message "Could not remove $($member.Name) from ${GroupName}: $msg"
                            }
                        }
                        Write-Host "  [INFO] Removed $removedCount unauthorized admin(s)" -ForegroundColor Cyan
                    }

                    Write-Host "Administrator group hardening complete" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Administrators group reset completed"
                } catch {
                    Write-Host "  [ERROR] Failed to harden Administrators: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "Failed to harden Administrators: $($_.Exception.Message)"
                    throw
                }
            }
        } else {
            Write-Host "Cleaning local Administrators group..." -ForegroundColor Cyan

            $ExclusionList = @("Administrator", "ccdcuser1")

            try {
                $GroupName = "Administrators"
                $adminMembers = Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue

                if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
                    Write-Host "  [INFO] ${GroupName} group is empty (Unexpected)" -ForegroundColor Yellow
                    Write-Log -Level "INFO" -Message "${GroupName} group is already empty"
                } else {
                    $removedCount = 0
                    foreach ($member in $adminMembers) {
                        try {
                            $username = $member.Name.Split('\')[-1]

                            if ($ExclusionList -contains $username) {
                                Write-Host "  [SKIP] Skipping ${username} (Protected Admin)" -ForegroundColor Magenta
                                Write-Log -Level "INFO" -Message "Skipped removal of ${username} from ${GroupName} group"
                                continue
                            }

                            Remove-LocalGroupMember -Group $GroupName -Member $member -Confirm:$false -ErrorAction Stop

                            Write-Host "  [SUCCESS] Removed ${username} from ${GroupName}" -ForegroundColor Green
                            Write-Log -Level "SUCCESS" -Message "Removed ${username} from ${GroupName}"
                            $removedCount++
                        } catch {
                            $msg = $_.Exception.Message
                            Write-Host "  [WARNING] Could not remove $($member.Name): $msg" -ForegroundColor Yellow
                            Write-Log -Level "WARNING" -Message "Could not remove $($member.Name) from ${GroupName}: $msg"
                        }
                    }
                    Write-Host "  [INFO] Removed $removedCount unauthorized admin(s)" -ForegroundColor Cyan
                }

                Write-Host "Administrator group hardening complete" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Administrators group reset completed"
            } catch {
                Write-Host "  [ERROR] Failed to harden Administrators: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Failed to harden Administrators: $($_.Exception.Message)"
                throw
            }
        }
    }
}
