<#
Author: https://github.com/byt3m
Description: This script checks for accounts with the flag "Account never expires" enabled.
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

$users = Get-ADUser -filter { userprincipalname -like "*" } -Property PasswordNeverExpires | `
            Where-Object { $_.PasswordNeverExpires -eq $True } | `
                Select-Object Name, SamAccountName, DistinguishedName, PasswordNeverExpires, Enabled

$users | Format-Table Name, SamAccountName, PasswordNeverExpires, Enabled


if (ReadInput -msg "Do you want to export it to CSV? (Y/N)"-yesno)
{
    $csv_name = (Get-Date -format "yyyyMMdd") + "_password_never_expire_users.csv"
    $csv_path = Join-Path $PSScriptRoot $csv_name
    $users | Export-Csv -Path $csv_path -Delimiter ";"
}