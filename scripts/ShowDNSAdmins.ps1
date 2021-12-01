<#
Author: https://github.com/byt3m
Description: This script shows the members of the DNSAdmins AD group.
#>

$members = @()

foreach ($l in ((Get-ADGroup DNSAdmins -Properties "*").Members -split "CN="))
{
    if (![System.String]::IsNullOrEmpty($l))
    {
        $members += "`t- CN=" + $l
    }
}

Write-Host "Members of DNSAdmins:" -ForegroundColor Yellow
Write-Host ($members -join "`n") -ForegroundColor Yellow