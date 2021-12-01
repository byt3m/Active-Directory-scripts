<#
Author: https://github.com/byt3m
Description: This script will check for inactive computer objects in an AD domain. A whitelist can be used.
#>

Clear-Host 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Host "Run the script as administrator" -ForegroundColor Red
	Exit
}

$white_list_path = Join-Path $PSScriptRoot "white_list.txt"

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
                if ($input -eq "N")
                {
                    return $false
                }
                elseif ($input -eq "Y")
                {
                    return $true
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

$white_list = Get-Content $white_list_path

$computers = Search-ADaccount -ComputersOnly -AccountInactive -Timespan 180 | `
    where-object { $_.Name -notin $white_list -and $_.LastLogonDate } | `
        Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, Enabled

$computers | Format-Table Name, SamAccountName, LastLogonDate, Enabled


if (ReadInput -msg "Do you want to export it to CSV? (Y/N)"-yesno)
{
    $csv_name = (Get-Date -format "yyyyMMdd") + "_inactive_computers.csv"
    $csv_path = Join-Path $PSScriptRoot $csv_name
    $computers | Export-Csv -Path $csv_path -Delimiter ";"
}