function Link-ServerWinRMGpo {
    <#
    .SYNOPSIS
        Keeps WinRM firewall access available for selected server computer accounts.
    .DESCRIPTION
        Creates or updates a domain GPO with inbound TCP 5985/5986 access, scoped to the
        selected computers. The WinRM service itself is left in its current state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [string[]]$RemoteAddress = @('LocalSubnet')
    )

    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }
    Invoke-HardeningOperation -OperationName 'Link WinRM Management GPO' -ScriptBlock {
        Add-CcdcWinRMAccessGpo -ComputerName $ComputerName -RemoteAddress $RemoteAddress
    }
}
