function Install-EternalBluePatch {
    [CmdletBinding()]
    param()

    $eternalBlueCompatible = @("Client7", "Client8", "Server2008", "Server2008R2", "Server2012", "Server2012R2")

    Invoke-HardeningOperation -OperationName "EternalBlue Mitigated" -OSCompatibility $eternalBlueCompatible -ScriptBlock {
        $patchUrlsFile = Join-Path $script:DataPath 'patchURLs.json'
        if (-not (Test-Path $patchUrlsFile)) {
            Write-Status -Level Warning "patchURLs.json not found in $script:DataPath (and could not be downloaded)." -LogMessage "patchURLs.json not found"
            throw "Required file not found"
        }

        $patchURLs = Get-Content -Raw -Path $patchUrlsFile | ConvertFrom-Json

        $patchURL = switch -Regex ($script:HardeningContext.OS.OSVersion) {
            '(?i)Vista'  { $patchURLs.Vista; break }
            'Windows 7'  { $patchURLs.'Windows 7'; break }
            'Windows 8'  { $patchURLs.'Windows 8'; break }
            '2008 R2'    { $patchURLs.'2008 R2'; break }
            '2008'       { $patchURLs.'2008'; break }
            '2012 R2'    { $patchURLs.'2012 R2'; break }
            '2012'       { $patchURLs.'2012'; break }
            default { throw "Unsupported OS version for EternalBlue patch: $($script:HardeningContext.OS.OSVersion)" }
        }

        Write-Host "Patch URL: $patchURL" -ForegroundColor Cyan

        $path = "$env:TEMP\eternalblue_patch.msu"

        Write-Host "Downloading patch file to $path" -ForegroundColor Cyan
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object Net.WebClient).DownloadFile($patchURL, $path)
            Write-Status -Level Success "Downloaded EternalBlue patch" -LogOnly
        } catch {
            Write-Status -Level Error "Failed to download EternalBlue patch: $($_.Exception.Message)"
            throw
        }

        Write-Host "Installing patch..." -ForegroundColor Cyan
        try {
            $process = Start-Process -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart" -Wait -PassThru
            if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
                throw "Patch installation returned exit code: $($process.ExitCode)"
            }
            Write-Status -Level Success "EternalBlue patch installed successfully" -LogOnly
        } catch {
            Write-Status -Level Error "Failed to install EternalBlue patch: $($_.Exception.Message)"
            throw
        } finally {
            if (Test-Path $path) {
                Remove-Item -Path $path -Force
            }
        }

        Write-Host "Patch for $($script:HardeningContext.OS.OSVersion) installed successfully!" -ForegroundColor Green
    }
}
