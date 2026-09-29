function Install-Splunk {
    [CmdletBinding()]
    param(
        [string]$Version,

        [Parameter(Mandatory=$true)]
        [string]$IP
    )

    Invoke-HardeningOperation -OperationName "Configure Splunk" -ScriptBlock {
        $splunkBeta = $true
        try {
            $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
            $splunkScript = Join-Path $env:TEMP 'splunk.ps1'

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $downloadURL -OutFile $splunkScript -UseBasicParsing
            Write-Log -Level "SUCCESS" -Message "Downloaded Splunk installation script"

            $splunkServer = "$($IP):9997"

            & $splunkScript $Version $splunkServer

            Write-Log -Level "SUCCESS" -Message "Splunk installation completed"
        } catch {
            Write-Log -Level "ERROR" -Message "Splunk installation failed: $($_.Exception.Message)"
            throw
        }
    }
}
