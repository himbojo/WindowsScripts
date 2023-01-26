function Find-Program {
    <#
.SYNOPSIS
    Returns a single or list of programs

.DESCRIPTION
    Find-Program is a function that returns a list of programs from
    the specified remote computer(s)

.PARAMETER ComputerName
    The remote computer(s) to check for programs on.

.PARAMETER Credential
    The Credentials to use

.EXAMPLE
    Find-Programs -ComputerName 'Server1', 'Server2'

.EXAMPLE
    Find-Programs -ComputerName 'Server1', 'Server2' -Credential (Get-Credential)

.INPUTS
    String

.OUTPUTS
    PSCustomObject

.NOTES
    Author:  Jordan Akroyd
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    $Output = @()
    $command = {
        $ComputerName = $env:COMPUTERNAME
        $RegistryUninstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        $RegistryObject = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$ComputerName)
        $RegistryKey = $RegistryObject.OpenSubKey($RegistryUninstall)
        $RegistryKeySubKeys=$RegistryKey.GetSubKeyNames()
        $SubKeyArrayList = New-Object -TypeName "System.Collections.ArrayList"
        foreach($key in $RegistryKeySubKeys){
            $KeyPath=$RegistryUninstall+"\\"+$key
            $SubKeyPath=$RegistryObject.OpenSubKey($KeyPath)
            $DisplayName=$SubKeyPath.GetValue("DisplayName")
            $UninstallString=$SubKeyPath.GetValue("UninstallString")
            if($DisplayName){
                $SubKeyCustomObject = New-Object System.Object
                $SubKeyCustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $DisplayName
                $SubKeyCustomObject | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $UninstallString
                $SubKeyArrayList.Add($SubKeyCustomObject) | Out-Null
            }
        }
        $SubKeyArrayList
    }
    foreach($machine in $ComputerName){
        if(!$Credential){
            $Output += Invoke-Command -ComputerName $machine -ScriptBlock $command
        } else {
            $Output += Invoke-Command -ComputerName $machine -ScriptBlock $command -Credential $Credential
        }
    }
    $Output
}
Find-Program -ComputerName $MachinesC  | where-object -property DisplayName -match 'silver'

