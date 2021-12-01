<#
Author: https://github.com/byt3m
Description: This script will export windows events from a given windows event channel to a CSV file.
#>

# GLOBALS
$logname = "" # Directory Service - single logname
$IDS = @("") # 2889 - multiple IDs
$CSV_name = ($env:COMPUTERNAME + "_" + $logname + ".csv").trim()
$CSV_delimiter = ";"
$CSV_path = Join-Path $env:USERPROFILE -ChildPath ("Desktop\" + $CSV_name)


# Main
$csv = @()
$entities = @()

Write-Host "Filtering eventlog..." -ForegroundColor Cyan

Get-WinEvent -FilterHashtable @{logname=$logname;id=$IDS} | foreach {

    $entity = ($_.Message -split "`n")[5].trim()

    if ($entity -notin $entities)
    {
        $entities += $entity

        $csv += [PSCustomObject]@{
            ID = $_.Id
            Fecha = $_.TimeCreated
            Proveedor = $_.ProviderName
            Mensaje = $_.Message
        }
    }

}

Write-Host "Saving CSV file to path `"$CSV_path`"." -ForegroundColor Cyan

$csv | Export-Csv -Path $CSV_path -Delimiter $CSV_delimiter