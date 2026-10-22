function Link-ServerServiceGpo {
    <#
    .SYNOPSIS
        Allows a service's firewall ports on the selected computer accounts.
    .DESCRIPTION
        Creates or updates the role's domain GPO (for example 'CCDC SSH Access'), links it
        at the domain root, and filters it to the selected computers. Ports: WinRM TCP
        5985/5986, SSH TCP 22, RDP TCP/UDP 3389, FTP TCP 21 plus IIS (ftpsvc) passive and
        active data, SMB TCP 445. The services themselves are left in their current state.
    .PARAMETER RemoteAddress
        Remote addresses allowed. Defaults to LocalSubnet for WinRM and Any for the others.
    .EXAMPLE
        Link-ServerServiceGpo -Role SSH -ComputerName LINUXGW01, FILE01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('WinRM', 'SSH', 'RDP', 'FTP', 'SMB')][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [string[]]$RemoteAddress
    )

    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }
    $operationName = if ($Role -eq 'WinRM') { 'Link WinRM Management GPO' } else { "Link $Role Access GPO" }
    Invoke-HardeningOperation -OperationName $operationName -ScriptBlock {
        Add-CcdcServiceRoleGpo -Role $Role -ComputerName $ComputerName -RemoteAddress $RemoteAddress
        if ($Role -eq 'FTP') {
            Write-Status -Level Warning "FTP data ports are allowed only for IIS FTP (ftpsvc). For FileZilla or another FTP server, add its passive range: Add-DomainFirewallPortRule -Name <name> -ComputerName <server> -Port '<low>-<high>'" `
                -LogMessage 'FTP role: passive/active data rules match only the IIS ftpsvc service'
        }
    }
}
