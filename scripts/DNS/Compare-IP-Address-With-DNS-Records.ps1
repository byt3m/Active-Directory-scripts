<#
Author: https://github.com/byt3m
Description: This script will change DNS records from a list of computer names.
#>


Clear-Host 

$ZoneName = "" # Domain name, example: CONTOSO.LOCAL
$TXTFile = "" # TXT file with format "computer_name;ip_address"

$TXTFileContent = Get-Content -Path $TXTFile
$computers_with_different_ip_address = @()

foreach ($line in $TXTFileContent)
{
    $TXT_ComputerName = ($line -split ";")[0].trim()
    $TXT_IP_Address = ($line -split ";")[1].trim()

    $results = Get-DnsServerResourceRecord -ZoneName $ZoneName | Where-Object { $_.HostName -eq $TXT_ComputerName }

    if ($results)
    {
        if ($results.Length -gt 1)
        {
            foreach ($record in $results)
            {
                $DNS_IP_Address = $record.RecordData.IPv4Address.IPAddressToString.trim()

                if ($DNS_IP_Address -ne $TXT_IP_Address)
                {
                    $computers_with_different_ip_address += [PSCustomObject]@{
                        Computer = $TXT_ComputerName
                        IP_address = $TXT_IP_Address
                        DNS_record = $DNS_IP_Address
                    }
                }
            }
        }
        else
        {
            $DNS_IP_Address = $results.RecordData.IPv4Address.IPAddressToString.trim()

            if ($DNS_IP_Address -ne $TXT_IP_Address)
            {
                $computers_with_different_ip_address += [PSCustomObject]@{
                    Computer = $TXT_ComputerName
                    IP_address = $TXT_IP_Address
                    DNS_record = $DNS_IP_Address
                }
            }
        }
    }
}

if ($computers_with_different_ip_address)
{
    $computers_with_different_ip_address | Format-Table
}
else
{
    Write-Host "Ok" -ForegroundColor Green
}