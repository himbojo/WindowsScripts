# Uninstall software
$MachinesC = @('localhost')
$command = { 
    Invoke-Expression "msiexec /x '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}' /qn"
    $StartTime = Get-Date
    while(!$log)
    {
        if((Get-Date).AddMinutes(-5) -ge $StartTime){
            Write-Error -Message "Houston, we have a problem." -ErrorAction Stop
        }
        $log = Get-EventLog -LogName 'Application' -Source 'MsiInstaller' -Message '*Removal completed successfully*' -After (Get-Date).AddMinutes(-5)
        Start-Sleep 1
    }
}
foreach($machine in $MachinesC) {
    Invoke-Command -ComputerName $machine -ScriptBlock $command
}