function Link-ServerRoleGpo {
    <#
    .SYNOPSIS
        Imports and links a firewall GPO for the selected server computer accounts.
    .DESCRIPTION
        The GPO is linked at the domain root with a computer-account security filter so
        only the named role servers receive it, even when several roles share an OU.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Web', 'Mail')][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][string]$BackupRoot
    )

    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }

    $gpoName = switch ($Role) {
        'Web'      { 'Web Servers Firewall Policy'; break }
        'Mail'     { 'Mail Servers Firewall Policy'; break }
    }

    Invoke-HardeningOperation -OperationName "Link $Role Server GPO" -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name $gpoName -BackupRoot $BackupRoot `
            -Target (Get-CcdcDomainRootDn) -SecurityFilter $ComputerName
    }
}
