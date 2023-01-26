# This script is designed to give you an idea on what AD records are "Stale"

# Last time the AD Object was logged into
$DaysInactive = 365
$time = (Get-Date).AddDays(( - ($DaysInactive)))

Write-Information "Retrieving AD Objects that have been inactive for greater than $DaysInactive Days..."
# Identify inactive computer accounts using last logon time stamp, only pulls 2000 entries
Get-ADComputer -Filter { LastLogonTimeStamp -lt $time } -ResultPageSize 2000 -resultSetSize $null -Properties Name, OperatingSystem, SamAccountName, DistinguishedName, LastLogonDate | Export-Csv -Path "~/Downloads/InactiveMachines_AD.csv"

Write-Information "Resolving Hostname of AD Objects..."
# Resolve DNS for an AD Entry
$csv = Import-Csv -Path "~/Downloads/InactiveMachines_AD.csv"
$i = 0
foreach ($computer in $csv) {
    $ProgressComplete = ($i/$csv.Count)*100
    Write-Progress -Activity "Resolving DNS: $($computer.DNSHostName)" -Status "$([math]::Round($ProgressComplete))%" -PercentComplete $ProgressComplete
    $i = $i + 1
    if ($computer.DNSHostName -ne "") {
        $dns = Resolve-DnsName $computer.DNSHostName -Type A -ErrorAction SilentlyContinue
        if ($dns) {
            if ($dns -is [System.Array]) {
                Add-Member -InputObject $computer -NotePropertyName "ResolveDNSName" -NotePropertyValue $dns[0].Name
                Add-Member -InputObject $computer -NotePropertyName "ResolveDNSIP" -NotePropertyValue $dns[0].IPAddress
            }
            else {
                Add-Member -InputObject $computer -NotePropertyName "ResolveDNSName" -NotePropertyValue $dns.Name
                Add-Member -InputObject $computer -NotePropertyName "ResolveDNSIP" -NotePropertyValue $dns.IPAddress
            }
        }
        else {
            Add-Member -InputObject $computer -NotePropertyName "ResolveDNSName" -NotePropertyValue $null
            Add-Member -InputObject $computer -NotePropertyName "ResolveDNSIP" -NotePropertyValue $null
        }
    }
}

Write-Information "Connecting to Hostname of AD Objects..."
# Attempt ping on AD Entry
$i = 0
foreach ($computer in $csv) {
    $ProgressComplete = ($i/$csv.Count)*100
    Write-Progress -Activity "Attemping Ping: $($computer.DNSHostName)" -Status "$([math]::Round($ProgressComplete))%" -PercentComplete $ProgressComplete
    $i = $i + 1
    if ($computer.DNSHostName -ne "") {
        $ComputerName = $computer.Name
        Set-Variable -Name "Status_$ComputerName" -Value (Test-Connection -ComputerName $computer.DNSHostName -Count 1 -AsJob)
    }
}

Write-Information "Retrieving results of connecting to Hostname of AD Objects..."
$i = 0
# If Ping Succeedes update CSV
foreach ($computer in $csv) {
    $ProgressComplete = ($i/$csv.Count)*100
    Write-Progress -Activity "Retrieving Ping Results: $($computer.DNSHostName)" -Status "$([math]::Round($ProgressComplete))%" -PercentComplete $ProgressComplete
    $i = $i + 1
    if ($computer.DNSHostName -ne "") {
        $ComputerName = $computer.Name
        $job = Get-Variable "Status_$ComputerName" -ValueOnly
        $Status = Wait-Job $job | Receive-Job
        if ($Status.ResponseTime) {
            Add-Member -InputObject $computer -NotePropertyName "ResponseTime" -NotePropertyValue $Status.ResponseTime
        }
        else {
            Add-Member -InputObject $computer -NotePropertyName "ResponseTime" -NotePropertyValue $null
        }
    }
    else {
        Add-Member -InputObject $computer -NotePropertyName "ResponseTime" -NotePropertyValue $null
    }
}

# clean up job variables used for parallel processing
Write-Information "Garbage collection of environment variables used..."
Remove-Variable "Status_*"
Write-Information "Garbage collection of files used..."
Remove-Item -Path "~/Downloads/InactiveMachines_AD.csv"
#$csv | Export-Csv -Path "~/Downloads/InactiveMachines.csv"

Write-Information "Deciding if Objects are Stale..."
$csv | ForEach-Object {
    if ([string]::IsNullOrWhiteSpace($_.ResolveDNSName) -and [string]::IsNullOrWhiteSpace($_.ResolveDNSIP) -and [string]::IsNullOrWhiteSpace($_.ResponseTime)) {
        Add-Member -InputObject $_ -NotePropertyName "Stale" -NotePropertyValue $true
    } else {
        Add-Member -InputObject $_ -NotePropertyName "Stale" -NotePropertyValue $null
    }
}

$InactivePath = "~/Downloads/InactiveMachines.csv"
Write-Information "Exporting CSV to $InactivePath..."
$csv | Export-Csv -Path $InactivePath

Write-Information "Displaying Stale Records..."
$csv | Where-Object {$_.Stale -eq $true} | Format-Table -Property DistinguishedName


# in excel
# if ResolveDNSName is blank
# and if ResolveDNSIP is blank
# and PingSucceeded is blank or false
# then the remaining entries are stale
