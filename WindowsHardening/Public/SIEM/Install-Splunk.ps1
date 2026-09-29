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
            Write-Status -Level Success "Downloaded Splunk installation script" -LogOnly

            $splunkServer = "$($IP):9997"

            & $splunkScript $Version $splunkServer

            Write-Status -Level Success "Splunk installation completed" -LogOnly
        } catch {
            Write-Status -Level Error "Splunk installation failed: $($_.Exception.Message)"
            throw
        }
    }
}
