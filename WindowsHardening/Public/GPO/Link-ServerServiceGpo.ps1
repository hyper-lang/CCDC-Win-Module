function Link-ServerServiceGpo {
    <#
    .SYNOPSIS
        Configures the selected role's service startup and firewall policy on the selected computer accounts.
    .DESCRIPTION
        Creates or updates the role's domain GPO (for example 'CCDC SSH Access'), links it
        at the domain root, and filters it to the selected computers. Ports: MSSQL TCP 1433
        and SQL Browser UDP 1434, WinRM TCP 5985/5986, SSH TCP 22, RDP TCP/UDP 3389, FTP
        TCP 21 plus IIS (ftpsvc) passive and active data, SMB TCP 445, Ping ICMP echo, and
        SNMP UDP 161/162. Supported service roles are set to automatic startup. Domain
        Users are added to the local Remote Desktop Users, OpenSSH Users, or Remote
        Management Users group for RDP, SSH, or WinRM respectively. This does not grant
        SQL/database, file-share, web, or application permissions.
    .PARAMETER RemoteAddress
        Remote addresses allowed. Defaults to Any for all service roles, including MSSQL
        and WinRM. SNMP is an optional/deprecated Windows feature and must be installed
        separately. MSSQL assumes the default instance; named instances need explicit ports.
    .EXAMPLE
        Link-ServerServiceGpo -Role SSH -ComputerName LINUXGW01, FILE01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Database', 'WinRM', 'SSH', 'RDP', 'FTP', 'SMB', 'Ping', 'SNMP')][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [string[]]$RemoteAddress
    ,
        [object]$State = $null,
        [string]$StepLabel
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }
    $operationName = if ($Role -eq 'WinRM') { 'Link WinRM Management GPO' } else { "Link $Role Access GPO" }
    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName $operationName -TargetComputerName $ComputerName -ScriptBlock {
        Add-CcdcServiceRoleGpo -Role $Role -ComputerName $ComputerName -RemoteAddress $RemoteAddress -State $State
        if ($Role -eq 'FTP') {
            Write-Status -Level Warning "FTP data ports are allowed only for IIS FTP (ftpsvc). For FileZilla or another FTP server, add its passive range: Add-DomainFirewallPortRule -Name <name> -ComputerName <server> -Port '<low>-<high>'" `
                -LogMessage 'FTP role: passive/active data rules match only the IIS ftpsvc service' -State $State
        }
    }
}
