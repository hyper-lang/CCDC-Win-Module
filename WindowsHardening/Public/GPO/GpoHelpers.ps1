# Internal helpers shared by the domain GPO operations.

$script:CcdcGpoArchiveUrl = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/gpos.zip'

$script:CcdcGpoBackups = @{
    'DC Allow AD' = '{A3C94A29-9136-44F8-BB0E-EE403AF937CC}'
    'Domain Allow AD + Core + Default Block' = '{CE93D39B-1489-4397-9631-A73F8E3D0404}'
    'Domain GPO Update Interval' = '{B39B6270-9D3A-4881-8A2B-7FA8B5DF4FE9}'
    'Domain Good-GPO' = '{9CDD7733-36C7-4306-B831-03C4C6D3FC80}'
    'Good-GPO' = '{F99C9DC5-C9F8-4C54-855D-23CA91CA7E7E}'
    'Domain Splomk' = '{2171A7B4-C5F4-4F48-A64B-4E95C605FB3C}'
    'Web Servers Firewall Policy' = '{00C38CA9-A53C-4CCF-A15F-E5BF927C43CE}'
    'Mail Servers Firewall Policy' = '{878525BA-78FC-4D60-B2A1-C66E712A6EAD}'
}

function Initialize-CcdcGpoEnvironment {
    [CmdletBinding()]
    param(
        [string]$GpoZipPath,
        [string]$GpoCachePath
    )

    foreach ($moduleName in @('ActiveDirectory', 'GroupPolicy')) {
        if (-not (Get-Module -Name $moduleName)) {
            Import-Module $moduleName -ErrorAction Stop
        }
    }

    if (-not $GpoCachePath) {
        $GpoCachePath = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-GPOs'
    }
    if (-not (Test-Path -LiteralPath $GpoCachePath)) {
        New-Item -Path $GpoCachePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if ($GpoZipPath) {
        if (-not (Test-Path -LiteralPath $GpoZipPath -PathType Leaf)) {
            throw "GPO archive not found: $GpoZipPath"
        }
        $archivePath = (Resolve-Path -LiteralPath $GpoZipPath -ErrorAction Stop).Path
    } else {
        $archivePath = Join-Path $GpoCachePath 'gpos.zip'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $script:CcdcGpoArchiveUrl -OutFile $archivePath -UseBasicParsing -ErrorAction Stop
        } catch {
            throw "Could not download GPO backups from $script:CcdcGpoArchiveUrl : $($_.Exception.Message)"
        }
    }

    $backupRoot = Join-Path $GpoCachePath 'Backups'
    if (-not (Test-Path -LiteralPath $backupRoot)) {
        New-Item -Path $backupRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $backupRoot -Force -ErrorAction Stop

    foreach ($backupId in $script:CcdcGpoBackups.Values | Select-Object -Unique) {
        $backupFolder = Join-Path $backupRoot $backupId
        if (-not (Test-Path -LiteralPath (Join-Path $backupFolder 'Backup.xml') -PathType Leaf)) {
            throw "GPO archive is missing backup $backupId"
        }
    }
    return $backupRoot
}

function Import-CcdcGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$BackupRoot
    )

    $backupId = $script:CcdcGpoBackups[$Name]
    if (-not $backupId) { throw "No bundled backup is mapped for GPO '$Name'" }

    Import-GPO -BackupId $backupId -Path $BackupRoot -TargetName $Name -CreateIfNeeded -ErrorAction Stop | Out-Null
    return (Get-GPO -Name $Name -ErrorAction Stop)
}

function Set-CcdcGpoSecurityFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string[]]$ComputerName = @(),
        [string[]]$GroupName = @()
    )

    $existingPermissions = @(Get-GPPermission -Name $Name -All -ErrorAction Stop)

    # Keep broad principals read-only so selected computer accounts control policy application.
    foreach ($principal in @(
        @{ Name = 'Authenticated Users'; Type = 'Group' }
        @{ Name = 'Domain Computers'; Type = 'Group' }
    )) {
        $existingPrincipal = @($existingPermissions | Where-Object {
            $_.Trustee.Name -eq $principal.Name
        })
        if ($existingPrincipal) {
            Set-GPPermissions -Name $Name -TargetName $principal.Name -TargetType $principal.Type `
                -PermissionLevel GpoRead -Replace -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }

    foreach ($permission in $existingPermissions) {
        $trusteeName = [string]$permission.Trustee.Name
        if ($trusteeName.EndsWith('$', [StringComparison]::Ordinal)) {
            Set-GPPermissions -Name $Name -TargetName $trusteeName -TargetType Computer `
                -PermissionLevel GpoRead -Replace -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }

    foreach ($computerIdentity in @($ComputerName | ForEach-Object { [string]$_ })) {
        if ([string]::IsNullOrWhiteSpace($computerIdentity)) { continue }
        $computer = Get-ADComputer -Identity $computerIdentity -ErrorAction Stop
        Set-GPPermissions -Name $Name -TargetName ([string]$computer.SamAccountName) -TargetType Computer `
            -PermissionLevel GpoApply -Replace -Confirm:$false -ErrorAction Stop | Out-Null
    }

    foreach ($groupIdentity in @($GroupName | ForEach-Object { [string]$_ })) {
        if ([string]::IsNullOrWhiteSpace($groupIdentity)) { continue }
        Set-GPPermissions -Name $Name -TargetName $groupIdentity -TargetType Group `
            -PermissionLevel GpoApply -Replace -Confirm:$false -ErrorAction Stop | Out-Null
    }
}

function Add-CcdcGpoLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [string[]]$SecurityFilter,
        [string[]]$SecurityFilterGroup,
        [switch]$Enforced
    )

    # Enforced links win over conflicting OU-linked GPOs and ignore Block Inheritance.
    $enforcedValue = if ($Enforced) { 'Yes' } else { 'No' }
    $inheritance = Get-GPInheritance -Target $Target -ErrorAction Stop
    $existingLink = @($inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $Name }) | Select-Object -First 1
    if ($existingLink) {
        Set-GPLink -Name $Name -Target $Target -LinkEnabled Yes -Enforced $enforcedValue -ErrorAction Stop | Out-Null
    } else {
        New-GPLink -Name $Name -Target $Target -LinkEnabled Yes -Enforced $enforcedValue -ErrorAction Stop | Out-Null
    }

    if ($SecurityFilter -and $SecurityFilter.Count -gt 0) {
        Set-CcdcGpoSecurityFilter -Name $Name -ComputerName $SecurityFilter -GroupName $SecurityFilterGroup
    } elseif ($SecurityFilterGroup -and $SecurityFilterGroup.Count -gt 0) {
        Set-CcdcGpoSecurityFilter -Name $Name -GroupName $SecurityFilterGroup
    }
}

function Invoke-CcdcGpoLinkOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [Parameter(Mandatory=$true)][string]$Target,
        [string[]]$SecurityFilter,
        [string[]]$SecurityFilterGroup,
        [switch]$Enforced
    )

    $gpo = Import-CcdcGpo -Name $Name -BackupRoot $BackupRoot
    Add-CcdcGpoLink -Name $gpo.DisplayName -Target $Target -SecurityFilter $SecurityFilter `
        -SecurityFilterGroup $SecurityFilterGroup -Enforced:$Enforced
    Write-Status -Level Success "Imported '$Name' and linked it to $Target" -LogMessage "Imported GPO '$Name' and linked to '$Target'"
}

function Get-CcdcDomainRootDn {
    (Get-ADDomain -ErrorAction Stop).DistinguishedName
}

function Get-CcdcDomainControllersOu {
    $domain = Get-ADDomain -ErrorAction Stop
    $targets = @()
    foreach ($domainController in Get-ADDomainController -Filter * -ErrorAction Stop) {
        $computerDn = $domainController.ComputerObjectDN
        if (-not $computerDn) {
            throw "Could not determine the computer object's distinguished name for domain controller '$($domainController.HostName)'"
        }
        $ouDn = $computerDn.Substring($computerDn.IndexOf(',') + 1)
        if (-not $ouDn.EndsWith($domain.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Domain controller object is outside the current domain: $computerDn"
        }
        $targets += $ouDn
    }
    $uniqueTargets = @($targets | Sort-Object -Unique)
    if ($uniqueTargets.Count -eq 0) { throw 'No domain controller computer objects were found in Active Directory.' }
    return ,$uniqueTargets
}

function Invoke-CcdcGpUpdate {
    [CmdletBinding()]
    param()

    $process = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' -Wait -PassThru -NoNewWindow -ErrorAction Stop
    if ($process.ExitCode -ne 0) {
        throw "gpupdate /force exited with code $($process.ExitCode)"
    }
}

function Set-CcdcGpoFirewallRule {
    # Creates or replaces one allow rule in a domain GPO. $Rule holds the remaining
    # New-NetFirewallRule parameters and must include Name.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][hashtable]$Rule
    )

    if (-not (Get-Module -Name NetSecurity)) { Import-Module NetSecurity -ErrorAction Stop }
    $policyStore = "$((Get-ADDomain -ErrorAction Stop).DNSRoot)\$GpoName"
    if (Get-NetFirewallRule -PolicyStore $policyStore -Name $Rule.Name -ErrorAction Ignore) {
        Remove-NetFirewallRule -PolicyStore $policyStore -Name $Rule.Name -ErrorAction Stop
    }
    New-NetFirewallRule -PolicyStore $policyStore -Action Allow -Enabled True @Rule -ErrorAction Stop | Out-Null
}

# Role GPOs created from scratch (no bundled backup). Rules are inbound unless noted;
# RemoteAddress is the default scope, overridable per call.
$script:CcdcServiceRoles = @{
    Database = @{
        GpoName = 'CCDC MSSQL Access'; RemoteAddress = @('Any')
        Rules = @(
            @{ Name = 'CCDC-Allow-MSSQL-TCP'; DisplayName = 'CCDC MSSQL (TCP-In)'; Protocol = 'TCP'; LocalPort = '1433' }
            @{ Name = 'CCDC-Allow-MSSQL-Browser-UDP'; DisplayName = 'CCDC MSSQL Browser (UDP-In)'; Protocol = 'UDP'; LocalPort = '1434' }
        )
    }
    WinRM = @{
        GpoName = 'CCDC Preserve WinRM'; RemoteAddress = @('Any')
        Rules = @(
            # WinRM listens through HTTP.sys (System), so a -Service WinRM filter never matches.
            @{ Name = 'CCDC-Allow-WinRM'; DisplayName = 'CCDC Preserve WinRM'; Protocol = 'TCP'; LocalPort = @('5985', '5986'); Program = 'System' }
        )
    }
    SSH = @{
        GpoName = 'CCDC SSH Access'; RemoteAddress = @('Any')
        Rules = @(
            @{ Name = 'CCDC-Allow-SSH'; DisplayName = 'CCDC SSH (TCP-In)'; Protocol = 'TCP'; LocalPort = '22' }
        )
    }
    RDP = @{
        GpoName = 'CCDC RDP Access'; RemoteAddress = @('Any')
        Rules = @(
            @{ Name = 'CCDC-Allow-RDP-TCP'; DisplayName = 'CCDC RDP (TCP-In)'; Protocol = 'TCP'; LocalPort = '3389' }
            @{ Name = 'CCDC-Allow-RDP-UDP'; DisplayName = 'CCDC RDP (UDP-In)'; Protocol = 'UDP'; LocalPort = '3389' }
        )
    }
    FTP = @{
        GpoName = 'CCDC FTP Access'; RemoteAddress = @('Any')
        Rules = @(
            @{ Name = 'CCDC-Allow-FTP'; DisplayName = 'CCDC FTP (TCP-In)'; Protocol = 'TCP'; LocalPort = '21' }
            # Stateful FTP does not open passive data ports, and its GPO setting is not honored.
            # These two follow the IIS FTP built-in rules, so they only match the ftpsvc service.
            @{ Name = 'CCDC-Allow-FTP-Passive'; DisplayName = 'CCDC FTP Passive Data (TCP-In)'; Protocol = 'TCP'; LocalPort = '1024-65535'; Service = 'ftpsvc' }
            @{ Name = 'CCDC-Allow-FTP-Active'; DisplayName = 'CCDC FTP Active Data (TCP-Out)'; Protocol = 'TCP'; LocalPort = '20'; Service = 'ftpsvc'; Direction = 'Outbound' }
        )
    }
    SMB = @{
        GpoName = 'CCDC SMB Access'; RemoteAddress = @('Any')
        Rules = @(
            @{ Name = 'CCDC-Allow-SMB'; DisplayName = 'CCDC SMB (TCP-In)'; Protocol = 'TCP'; LocalPort = '445'; Program = 'System' }
        )
    }
}

function Add-CcdcServiceRoleGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [string[]]$RemoteAddress
    )

    $definition = $script:CcdcServiceRoles[$Role]
    if (-not $definition) { throw "Unknown service role '$Role'" }
    if (-not $RemoteAddress) { $RemoteAddress = $definition.RemoteAddress }
    $gpoName = $definition.GpoName
    $gpo = Get-GPO -Name $gpoName -ErrorAction Ignore
    if (-not $gpo) {
        $gpo = New-GPO -Name $gpoName -ErrorAction Stop
    }

    foreach ($rule in $definition.Rules) {
        $ruleParams = @{ Direction = 'Inbound'; RemoteAddress = $RemoteAddress }
        foreach ($key in $rule.Keys) { $ruleParams[$key] = $rule[$key] }
        Set-CcdcGpoFirewallRule -GpoName $gpoName -Rule $ruleParams
    }

    Add-CcdcGpoLink -Name $gpo.DisplayName -Target (Get-CcdcDomainRootDn) -SecurityFilter $ComputerName
    Write-Status -Level Success "Created/updated '$gpoName' for $($ComputerName -join ', ')" `
        -LogMessage "Created/updated '$gpoName' ($($RemoteAddress -join ', ')) for computer account(s): $($ComputerName -join ', ')"
}
