function Find-Program {
    <#
.SYNOPSIS
    Returns a single or list of programs

.DESCRIPTION
    Find-Program is a function that returns a list of programs from
    the specified remote computer(s)

.PARAMETER ComputerName
    Hostname(s) or IP Address(es) of the target system.

.PARAMETER ProgramName
    Program you are looking for, will match on any substring and is case-insensitive

.PARAMETER TimeOut
    How long you are willing to wait for each computer to be checked, in seconds

.PARAMETER Credential
    Credentials to log into the machine

.EXAMPLE
    PS> Find-Program -ComputerName "Server1"

.EXAMPLE
    PS> "Server1","Server2" | Find-Program

.INPUTS
    System.String ComputerName

.OUTPUTS
    Array of PSCustomObject

.NOTES
        Filename:       Find-Program.ps1
        Author:         https://github.com/himbojo
        Modified date:  26-01-2023
        Version:        1.0
    
    .LINK
        https://github.com/himbojo/WindowsScripts
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [Alias('IPAddress', 'Server', 'Computer')]    
        [string]$ComputerName,
        [Parameter(Mandatory = $false, Position = 1)]
        [Alias('Program', 'ProgramString', 'String')]    
        [string]$ProgramName,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(1, 60)]
        [int]$TimeOut = 3,
        [Parameter(Mandatory = $false, Position = 3)]
        [System.Management.Automation.PSCredential]$Credential
    )
    Begin {
        $command = {
            $ComputerName = $env:COMPUTERNAME
            $RegistryUninstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            $RegistryObject = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $RegistryKey = $RegistryObject.OpenSubKey($RegistryUninstall)
            $RegistryKeySubKeys = $RegistryKey.GetSubKeyNames()
            $SubKeyArrayList = New-Object -TypeName "System.Collections.ArrayList"
            foreach ($key in $RegistryKeySubKeys) {
                $KeyPath = $RegistryUninstall + "\\" + $key
                $SubKeyPath = $RegistryObject.OpenSubKey($KeyPath)
                $DisplayName = $SubKeyPath.GetValue("DisplayName")
                $UninstallString = $SubKeyPath.GetValue("UninstallString")
                if ($DisplayName) {
                    $SubKeyCustomObject = New-Object System.Object
                    $SubKeyCustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $DisplayName
                    $SubKeyCustomObject | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $UninstallString
                    $SubKeyArrayList.Add($SubKeyCustomObject) | Out-Null
                }
            }
            $SubKeyArrayList
        }
    }
    Process {
        $Separator = "`n$("=" * 50)`n"
        Write-Output "$Separator$ComputerName$Separator"
        $FQDN = @((Resolve-DnsName $ComputerName -Type A -QuickTimeout -ErrorAction SilentlyContinue).Name)[0]
        if (!$FQDN) {
            Write-Error "Could not resolve $ComputerName."
            return
        }
        if (Test-WSMan -ComputerName $FQDN -ErrorAction Ignore) {
            if (!$Credential) {
                $remote = Invoke-Command -ComputerName $FQDN -ScriptBlock $command -AsJob
                $Output = Wait-Job $remote -Timeout $TimeOut | Receive-Job | Select-Object -Property DisplayName, UninstallString
            }
            else {
                $remote = Invoke-Command -ComputerName $FQDN -ScriptBlock $command -Credential $Credential -AsJob
                $Output = Wait-Job $remote -Timeout $TimeOut | Receive-Job | Select-Object -Property DisplayName, UninstallString
            }
            if ($ProgramName) {
                $Output = $Output | Where-Object -property DisplayName -Match $ProgramName
            }
            Write-Output $Output
        }
        else {
            Write-Error "Couldn't connect to $ComputerName."
        }
        
    }
}
