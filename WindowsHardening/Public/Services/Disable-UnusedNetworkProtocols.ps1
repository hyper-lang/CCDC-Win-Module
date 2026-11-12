function Disable-UnusedNetworkProtocols {
    [CmdletBinding()]
    param([object]$State = $null, [string]$StepLabel)
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName "Disable Unused Network Protocols" -ScriptBlock {
        $activeAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" })
        $problems = 0

        foreach ($adapter in $activeAdapters) {
            try {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop
                Write-Status -Level Success "Disabled IPv6 on adapter: $($adapter.Name)" -LogOnly -State $State
            } catch {
                $problems++
                Write-Status -Level Warning "Could not disable IPv6 on adapter $($adapter.Name): $($_.Exception.Message)" -State $State
            }
        }

        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop

            foreach ($adapter in $adapters) {
                # SetTcpipNetbios returns 0 on success, 1 when a restart is needed; anything else failed.
                $result = $adapter.SetTcpipNetbios(2).ReturnValue
                if ($result -in 0, 1) {
                    Write-Status -Level Success "Disabled NetBIOS over TCP/IP on adapter: $($adapter.Description)" -LogOnly -State $State
                } else {
                    $problems++
                    Write-Status -Level Warning "Could not disable NetBIOS on adapter $($adapter.Description) (SetTcpipNetbios returned $result)" -State $State
                }
            }
        } catch {
            $problems++
            Write-Status -Level Warning "Could not get network adapters: $($_.Exception.Message)" -State $State
        }

        if ($problems -eq 0) {
            Write-Status -Level Success "Unused network protocols disabled (IPv6, NetBIOS)" -State $State
        } else {
            Write-Status -Level Warning "Unused network protocols partly disabled: $problems problem(s) above" -State $State
        }
    }
}
