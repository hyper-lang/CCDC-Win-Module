function Disable-UnusedNetworkProtocols {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Disable Unused Network Protocols" -ScriptBlock {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

        if ($activeAdapters) {
            foreach ($adapter in $activeAdapters) {
                try {
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
                    Write-Log -Level "SUCCESS" -Message "Disabled IPv6 on adapter: $($adapter.Name)"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable IPv6 on adapter $($adapter.Name): $($_.Exception.Message)"
                }
            }
        }

        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"

            foreach ($adapter in $adapters) {
                try {
                    $adapter.SetTcpipNetbios(2) | Out-Null
                    Write-Log -Level "SUCCESS" -Message "Disabled NetBIOS over TCP/IP on adapter"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable NetBIOS: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log -Level "WARNING" -Message "Could not get network adapters: $($_.Exception.Message)"
        }

        Write-Host "Unused network protocols disabled (IPv6, NetBIOS)" -ForegroundColor Green
    }
}

Set-Alias -Name Disable-UnnecessaryServices -Value Disable-UnusedNetworkProtocols
