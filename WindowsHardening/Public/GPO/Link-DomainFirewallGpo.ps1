function Link-DomainFirewallGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Firewall GPO' -ScriptBlock {
        $gpoName = 'Domain Allow AD + Core + Default Block'
        # Applies to every computer, DCs included; 'DC Allow AD' adds the DC rules on top.
        # The explicit filter also undoes the Domain Computers-only filter of older runs.
        Invoke-CcdcGpoLinkOperation -Name $gpoName -BackupRoot $BackupRoot `
            -Target (Get-CcdcDomainRootDn) -SecurityFilterGroup @('Authenticated Users') -Enforced
        # Default outbound Block otherwise stops time sync (members to DCs, DCs to the PDC,
        # the PDC to its upstream source), and Kerberos fails once clocks drift.
        Set-CcdcGpoFirewallRule -GpoName $gpoName -Rule @{
            Name = 'CCDC-NTP-Out'; DisplayName = 'CCDC NTP (UDP-Out)'
            Direction = 'Outbound'; Protocol = 'UDP'; RemotePort = '123'
        }
    }
}
