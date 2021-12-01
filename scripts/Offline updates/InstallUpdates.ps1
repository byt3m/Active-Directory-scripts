<#
Author: https://github.com/byt3m
Description: This script will install autmatically .MSU updates.
#>

Clear-Host 

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

while ($true)
{
    $UpdatePath = ReadInput -msg "Path to directory containing updates"

    if (Test-Path -Path $UpdatePath)
    {
        Break
    }
}

Write-Host "Checking for .MSU files." -ForegroundColor Cyan
$Updates = Get-ChildItem -Path $UpdatePath -Recurse | Where-Object {$_.Extension -eq ".msu"}

if (!$Updates)
{
    Write-host "No .MSU files found in directory `"$UpdatePath`"." -ForegroundColor Yellow
    Exit
}

Write-Host "Found updates, installing them..." -ForegroundColor Cyan

ForEach ($update in $Updates) 
{
    $UpdateFilePath = $update.FullName
    write-host "Installing update $($update.BaseName)" -ForegroundColor Yellow
    Start-Process -wait wusa -ArgumentList "/update $UpdateFilePath","/quiet","/norestart"
}