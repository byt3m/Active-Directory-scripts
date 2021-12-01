<#
Author: https://github.com/byt3m
Description: This script will write the Email attribute of a list of AD users contained in a CSV file.
#>

$csv_path = ""


$csv_content = Get-Content -Path $csv_path 

foreach($line in $csv_content)
{
    # Get data
    $AD_username = ($line -split ";")[0].trim()
    $email_address = ($line -split ";")[1].trim()

    # Check strings
    if ([string]::IsNullOrEmpty($AD_username) -or [string]::IsNullOrEmpty($email_address))
    {
        Write-Warning "Skipping line `"$line`". No AD or Office 365 user"
        continue
    }

    # Check user in AD
    try
    {
        $AD_user_object = Get-ADUser $AD_username 
    }
    Catch
    {
        Write-Warning "[!] User `"$AD_username`" not found in Active Directory."
        continue
    }

    # Change mail
    Write-Host "[-] Changing mail of user `"$AD_username`" to `"$email_address`"" -ForegroundColor Cyan
    try
    {
        Set-ADUser $AD_user_object -EmailAddress $email_address
    }
    Catch
    {
        Write-Error "[X] Error changing email address of user `"$AD_username`""
        continue
    }

    # Check mail    
    $AD_user_object = Get-ADUser $AD_username -Properties "EmailAddress"
    if ($AD_user_object.EmailAddress -ne $email_address)
    {
        Write-Warning "[!] Email address of user `"$AD_username`" did not change!!"
    }
}