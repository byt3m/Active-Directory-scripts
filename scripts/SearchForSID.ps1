<#
Author: https://github.com/byt3m
Description: This script will search a given SID in an AD domain.
#>

Clear-Host 

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

# Ask for the SID
$ObjectSID = ReadInput -msg "Enter the SID"

# Read AD users, groups and computers
$Users = Get-ADUser -Filter { samaccountname -like "*" } -properties SID | Where-Object { $_.SID -eq $ObjectSID }
$Groups = Get-ADGroup -Filter { samaccountname -like "*" } -properties SID | Where-Object { $_.SID -eq $ObjectSID }
$Computers = Get-ADComputer -Filter { samaccountname -like "*" } -properties SID | Where-Object { $_.SID -eq $ObjectSID }

Clear-Host

# Show the results for users
if ($Users)
{
    Write-Host "Found an USER matching the SID '$ObjectSID'!" -ForegroundColor Cyan
    $Users | Format-Table Name, SamAccountName, DistinguishedName, SID
}

# Show the results for groups
if ($Groups)
{
    Write-Host "Found a GROUP matching the SID '$ObjectSID'!" -ForegroundColor Cyan
    $Groups | Format-Table Name, SamAccountName, DistinguishedName, SID
}

# Show the results for computers
if ($Computers)
{
    Write-Host "Found a COMPUTER matching the SID '$ObjectSID'!" -ForegroundColor Cyan
    $Computers | Format-Table Name, SamAccountName, DistinguishedName, SID
}

# Show a message if there are no results
if (!$Users -and !$Groups -and !$Computers)
{
    Write-Host "No results found" -ForegroundColor Yellow
}