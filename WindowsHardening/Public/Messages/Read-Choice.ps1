#Requires -Version 5.1

# Read-Choice.ps1 - Numbered/keyed prompt for menus, sub-menus, and lists (one or many answers).

function Read-Choice {
    <#
    .SYNOPSIS
        Shows a list of options and reads one or more choices.
    .DESCRIPTION
        Each option is a string or a hashtable with:
          Key      - what the user types (default: its 1-based position)
          Label    - text shown next to the key (required for hashtables)
          Value    - what is returned (default: Key)
          Section  - optional header; printed when it changes from the previous option

        Input:
          - A key selects that option (case-insensitive).
          - With -Multiple: several keys separated by commas or spaces, and ranges such
            as 5-8, which select every listed option whose key is a number in that range.
          - With -AllowCustom: a value that is not a key is passed through -ValidateCustom
            (if given) and returned as-is; -ValidateCustom may return a normalized value or
            throw to reject it.
          - Enter with -Default returns the defaults; Q with -AllowQuit returns $null.
        Invalid input is reported and the prompt repeats.

        Returns a single value, or an array with -Multiple (in the order typed, no
        duplicates).
    .EXAMPLE
        Read-Choice -Prompt "Protocol" -Options 'TCP', 'UDP', 'Both' -Default 'TCP'
    .EXAMPLE
        $ports = Read-Choice -Prompt "Ports" -Multiple -AllowCustom -Options @(
            @{ Key = '53'; Label = 'DNS'; Value = 53 }
            @{ Key = '389'; Label = 'LDAP'; Value = 389 }
        ) -ValidateCustom { param($v) (ConvertTo-PortList -Ports $v)[0] }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [object[]]$Options = @(),

        [string]$Title,

        [switch]$Multiple,

        [switch]$AllowCustom,

        [scriptblock]$ValidateCustom,

        # Keys selected when the user just presses Enter.
        [string[]]$Default,

        [switch]$AllowQuit,

        [string]$QuitLabel = 'Cancel'
    )

    # -- Normalize options ---------------------------------------------------
    $items = @()
    $position = 0
    foreach ($option in $Options) {
        $position++
        if ($option -is [System.Collections.IDictionary]) {
            $key = if ($null -ne $option.Key) { "$($option.Key)" } else { "$position" }
            $items += [PSCustomObject]@{
                Key     = $key
                Label   = "$($option.Label)"
                Value   = if ($option.Contains('Value')) { $option.Value } else { $key }
                Section = $option.Section
            }
        } else {
            $items += [PSCustomObject]@{ Key = "$position"; Label = "$option"; Value = "$option"; Section = $null }
        }
    }
    if ($items.Count -eq 0 -and -not $AllowCustom) {
        throw "Read-Choice needs -Options or -AllowCustom"
    }
    $byKey = @{}
    foreach ($item in $items) { $byKey[$item.Key.ToUpper()] = $item }

    # -- Display -------------------------------------------------------------
    if ($Title) { Write-Banner $Title -Style Inline -Color Green }
    $keyWidth = ($items | ForEach-Object { $_.Key.Length } | Measure-Object -Maximum).Maximum
    if ($AllowQuit -and $keyWidth -lt 1) { $keyWidth = 1 }
    $currentSection = $null
    foreach ($item in $items) {
        if ($item.Section -and $item.Section -ne $currentSection) {
            Write-Banner $item.Section -Style Inline
            $currentSection = $item.Section
        }
        $marker = if ($Default -contains $item.Key) { ' *' } else { '' }
        Write-Host ("  {0}) {1}{2}" -f $item.Key.PadLeft($keyWidth), $item.Label, $marker)
    }
    if ($AllowQuit) {
        Write-Host ("`n  {0}) {1}" -f 'Q'.PadLeft($keyWidth), $QuitLabel) -ForegroundColor DarkGray
    }

    $hints = @()
    if ($Multiple) { $hints += 'one or more, e.g. 1,3,5-7' }
    if ($AllowCustom) { $hints += 'or type values not listed' }
    if ($Default) { $hints += "Enter = defaults (*)" }
    if ($hints) { Write-Host ("  (" + ($hints -join '; ') + ")") -ForegroundColor DarkGray }

    # -- Read until valid ----------------------------------------------------
    while ($true) {
        try {
            $raw = Read-Host $Prompt
        } catch {
            throw "Read-Choice: cannot prompt in this session (no interactive console). Pass the value as a parameter instead. $($_.Exception.Message)"
        }
        $raw = "$raw".Trim()

        if ($raw -eq '' -and $Default) {
            $tokens = $Default
        } elseif ($AllowQuit -and $raw -match '^(?i)q$') {
            return $null
        } elseif ($raw -eq '') {
            Write-Host "  Please make a selection." -ForegroundColor Yellow
            continue
        } else {
            $tokens = @($raw -split '[,\s]+' | Where-Object { $_ })
        }

        if (-not $Multiple -and $tokens.Count -gt 1) {
            Write-Host "  Choose only one." -ForegroundColor Yellow
            continue
        }

        $result = New-Object System.Collections.ArrayList
        $problem = $null
        foreach ($token in $tokens) {
            $upper = $token.ToUpper()
            if ($byKey.ContainsKey($upper)) {
                [void]$result.Add($byKey[$upper].Value)
            } elseif ($Multiple -and $token -match '^(\d+)-(\d+)$') {
                $low = [int]$Matches[1]; $high = [int]$Matches[2]
                $inRange = @($items | Where-Object { $_.Key -match '^\d+$' -and [int]$_.Key -ge $low -and [int]$_.Key -le $high })
                if ($inRange.Count -eq 0) { $problem = "No listed option in range $token"; break }
                foreach ($item in $inRange) { [void]$result.Add($item.Value) }
            } elseif ($AllowCustom) {
                try {
                    $value = if ($ValidateCustom) { & $ValidateCustom $token } else { $token }
                    [void]$result.Add($value)
                } catch {
                    $problem = "'$token': $($_.Exception.Message)"; break
                }
            } else {
                $problem = "'$token' is not an option"; break
            }
        }
        if ($problem) {
            Write-Host "  $problem. Try again." -ForegroundColor Yellow
            continue
        }

        # De-duplicate, keeping the order typed.
        $seen = @{}
        $unique = @($result | Where-Object { $k = "$_"; if ($seen.ContainsKey($k)) { $false } else { $seen[$k] = $true; $true } })

        if ($Multiple) { return ,$unique }
        return $unique[0]
    }
}
