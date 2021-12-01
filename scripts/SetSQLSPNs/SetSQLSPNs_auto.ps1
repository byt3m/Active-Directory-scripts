Clear-Host

Write-Host "`nAutomatic operational mode selected.`n" -ForegroundColor Yellow

While ($true)
{
    $file_path = ReadInput -msg "Enter the path to the file containing the server names"

    if (!(Test-Path -Path $file_path))
    {
        Write-Host "File `"$file_path`" does not exist" -ForegroundColor Red
        continue
    }

    break
}

$file_content = Get-Content -Path $file_path -Force

foreach ($server_name in $file_content)
{
    if (!(CheckADComputer -computer $server_name))
    {
        Write-Host "Computer `"$server_name`" does not exist in Active Directory." -ForegroundColor Red
        continue
    }


    $SPNs = @( ("MSSQLSvc/" + $server_name + "." + $domain_FQDN), `
               ("MSSQLSvc/" + $server_name + "." + $domain_FQDN + ":" + $MSSQL_port) )

    $current_spns = setspn -L $service_account

    foreach ($spn in $SPNs)
    {
        Write-Host "Adding SPN `"$spn`" to account `"$service_account`"" -ForegroundColor Cyan

        if ($current_spns -match $spn)
        {
            Write-Host "Account `"$service_account`" already has the SPN `"$spn`"" -ForegroundColor Red
            continue
        }
        
        Write-Host "OK" -ForegroundColor Green
        $result = setspn $service_account -a $spn
    }
}