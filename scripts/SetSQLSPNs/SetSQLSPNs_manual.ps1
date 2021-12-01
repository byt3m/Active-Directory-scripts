Clear-Host

Write-Host "`nManual operational mode selected.`n" -ForegroundColor Yellow

While ($true)
{
    $server_name = ReadInput -msg "Server name"

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
