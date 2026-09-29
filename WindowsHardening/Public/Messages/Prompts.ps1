#Requires -Version 5.1

# Prompts.ps1 - Interactive prompts: yes/no, comma-separated lists, hidden input.

function Read-YesNo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [switch]$Force
    )

    try {
        if ($Force) {
            return 'y'
        }

        do {
            Write-Host $Message -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -ieq 'y' -or $response -ieq 'n') {
                return $response
            } else {
                Write-Host "Please enter 'y' or 'n'." -ForegroundColor Yellow
            }
        } while ($true)
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Read-YesNo: $($_.Exception.Message)"
        return "n"
    }
}

function Read-CommaList {
    [CmdletBinding()]
    param(
        [string]$Category,
        [string]$Message
    )

    try {
        $userInput = $null
        if ($Message -ne "") {
            $userInput = Read-Host -Prompt $Message
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        } elseif ($Category -ne "") {
            $userInput = Read-Host -Prompt "List $Category. Separate by commas if multiple. NO SPACES"
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Read-CommaList: $($_.Exception.Message)"
        return @()
    }
}

function Read-SecretInput {
    param([string]$Prompt)
    Write-Host -NoNewline $Prompt
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $input
}
