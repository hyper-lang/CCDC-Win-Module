function Install-EternalBluePatch {
    [CmdletBinding()]
    param([object]$State = $null,
        [string]$StepLabel
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    $eternalBlueCompatible = @("Client7", "Client8", "Server2008", "Server2008R2", "Server2012", "Server2012R2")

    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName "Install EternalBlue Patch" -OSCompatibility $eternalBlueCompatible -ScriptBlock {
        $patchUrlsFile = Join-Path $script:DataPath 'patchURLs.json'
        if (-not (Test-Path $patchUrlsFile)) {
            Write-Status -Level Warning "patchURLs.json not found in $script:DataPath (and could not be downloaded)." -LogMessage "patchURLs.json not found" -State $State
            throw "Required file not found"
        }

        $patchURLs = Get-Content -Raw -Path $patchUrlsFile | ConvertFrom-Json

        $patchURL = switch -Regex ($State.Context.OS.OSVersion) {
            '(?i)Vista'  { $patchURLs.Vista; break }
            'Windows 7'  { $patchURLs.'Windows 7'; break }
            'Windows 8'  { $patchURLs.'Windows 8'; break }
            '2008 R2'    { $patchURLs.'2008 R2'; break }
            '2008'       { $patchURLs.'2008'; break }
            '2012 R2'    { $patchURLs.'2012 R2'; break }
            '2012'       { $patchURLs.'2012'; break }
            default { throw "Unsupported OS version for EternalBlue patch: $($State.Context.OS.OSVersion)" }
        }

        Write-Status "Patch URL: $patchURL" -State $State

        $path = "$env:TEMP\eternalblue_patch.msu"

        Write-Status "Downloading patch file to $path" -State $State
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            (New-Object Net.WebClient).DownloadFile($patchURL, $path)
            Write-Status -Level Success "Downloaded EternalBlue patch" -LogOnly -State $State
        } catch {
            Write-Status -Level Error "Failed to download EternalBlue patch: $($_.Exception.Message)" -State $State
            throw
        }

        Write-Status "Installing patch (wusa)..." -State $State
        try {
            # wusa exit codes: 0 = installed, 3010 = installed (restart required),
            # 2359302 (0x240006) = already installed, -2145124329 (0x80240017, as a signed int) = not applicable.
            $process = Start-Process -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart" -Wait -PassThru
            switch ($process.ExitCode) {
                0          { Write-Status -Level Success "EternalBlue patch installed successfully" -LogOnly -State $State }
                3010       { Write-Status -Level Success "EternalBlue patch installed - restart required to finish" -State $State }
                2359302    { Write-Status -Level Success "EternalBlue patch was already installed" -State $State }
                -2145124329 { throw "Patch is not applicable to this system (wusa 0x80240017) - check the OS version and patchURLs.json" }
                default    { throw "Patch installation returned exit code: $($process.ExitCode)" }
            }
        } catch {
            Write-Status -Level Error "Failed to install EternalBlue patch: $($_.Exception.Message)" -State $State
            throw
        } finally {
            if (Test-Path $path) {
                Remove-Item -Path $path -Force
            }
        }

    }
}
