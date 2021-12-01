<#
Author: https://github.com/byt3m
Description: This script will check for Windows updates offline by using the wsusscn2.cab Microsoft provided file.
#>

Clear-Host 

# Admin check 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Host "Run the script as administrator" -ForegroundColor Red
	Exit
}

function ReadInput
{
    Param ( [string] $msg, [switch] $secure, [switch]$yesno ) 

    while ( $true )
    {
        if ($secure)
        {
            $input = Read-Host $msg -AsSecureString
        }
        else
        {
            $input = Read-Host $msg
        }

        if ( $input )
        {
            if ($yesno)
            {
                if ($input -eq "N" -or $input -eq "Y")
                {
                    break
                }
                else
                {
                    Write-Warning "Write 'N' for No or 'Y' for Yes"
                }
            }
            else
            {
                break
            }
        }
    }

    return $input.Trim()
}

if (Test-Path -Path "wsusscn2.cab")
{
    $wsusscn2 = Get-Item "wsusscn2.cab"
}
else
{
    while ($true)
    {
        $wsusscn2 = ReadInput -msg "Path to file 'wsusscn2.cab'"

        if (Test-Path -Path $wsusscn2)
        {
            Break
        }
    }
}

Write-Host "Reading file `"wsusscn2.cab`"" -ForegroundColor Cyan

#Using WUA to Scan for Updates Offline with PowerShell 
#VBS version: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/aa387290(v=vs.85)
 
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager
$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $wsusscn2, 1)
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
 
Write-Output "Searching for updates... `r`n" 
 
$UpdateSearcher.ServerSelection = 3 #ssOthers

$UpdateSearcher.IncludePotentiallySupersededUpdates = $true # good for older OSes, to include Security-Only or superseded updates in the result list, otherwise these are pruned out and not returned as part of the final result list
 
$UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString() 
 
$SearchResult = $UpdateSearcher.Search("IsInstalled=0") # or "IsInstalled=0 or IsInstalled=1" to also list the installed updates as MBSA did 
 
$Updates = $SearchResult.Updates 
 
if($Updates.Count -eq 0)
{ 
    Write-Output "There are no applicable updates." 
    return $null 
} 
 
Write-Output "List of applicable items on the machine when using wssuscan.cab: `r`n" 
 
$i = 0 
$to_export = @()
foreach($Update in $Updates)
{  
    Write-Output "$($i)> $($Update.Title)"
    $to_export += $Update.Title
    $i++
}

$to_export_path = Join-Path $PSScriptRoot "updates.txt"
($to_export -join "`n") > $to_export_path