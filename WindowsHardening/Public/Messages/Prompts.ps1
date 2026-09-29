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

function Read-SecretInput {
    param([string]$Prompt)
    Write-Host -NoNewline $Prompt
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $input
}
