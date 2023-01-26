# get size of folder, in this case logs
$dir = Get-ChildItem | Where-Object { $_.PSISContainer }
foreach ($d in $dir){
    $path = $d.FullName
    $path
    (Get-ChildItem $path | Measure-Object Length -s).sum / 1Mb
}
(Get-ChildItem Logs | Measure-Object Length -s).sum / 1Mb
