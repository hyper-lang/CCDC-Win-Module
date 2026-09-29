function Disable-UnusedNetworkProtocols {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Disable Unused Network Protocols" -ScriptBlock {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

        if ($activeAdapters) {
            foreach ($adapter in $activeAdapters) {
                try {
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
                    Write-Status -Level Success "Disabled IPv6 on adapter: $($adapter.Name)" -LogOnly
                } catch {
                    Write-Status -Level Warning "Could not disable IPv6 on adapter $($adapter.Name): $($_.Exception.Message)"
                }
            }
        }

        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"

            foreach ($adapter in $adapters) {
                try {
                    $adapter.SetTcpipNetbios(2) | Out-Null
                    Write-Status -Level Success "Disabled NetBIOS over TCP/IP on adapter" -LogOnly
                } catch {
                    Write-Status -Level Warning "Could not disable NetBIOS: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Status -Level Warning "Could not get network adapters: $($_.Exception.Message)"
        }

        Write-Host "Unused network protocols disabled (IPv6, NetBIOS)" -ForegroundColor Green
    }
}
