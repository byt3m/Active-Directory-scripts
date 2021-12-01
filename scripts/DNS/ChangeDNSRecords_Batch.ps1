<#
Author: https://github.com/byt3m
Description: This script will change DNS records from a list of computer names.
#>


Clear-Host 

$ZoneName = "" # Domain name, example: CONTOSO.LOCAL
$TXTFile = "" # TXT file with format "computer_name;ip_address"

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
                    if ($input -eq "N") { return 0; }
                    elseif ($input -eq "y") { return 1; }
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
    
    if ( (ReadInput -msg "Do you want the script to modify the DNS records with the supplied IP addresses? (Y/N)" -yesno) -eq 1 )
    {
        foreach ($entry in $computers_with_different_ip_address)
        {
            $DNSRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName | Where-Object { $_.HostName -eq $entry.Computer }   
            $NewDNSRecord = $DNSRecord.Clone()         
            Try 
            {
                $NewDNSRecord.RecordData.IPv4Address = [System.Net.IPAddress]::parse($entry.IP_address)
                Set-DnsServerResourceRecord -NewInputObject $NewDNSRecord -OldInputObject $DNSRecord -ZoneName $ZoneName 
            }
            Catch { }
        }
    }
}
else
{
    Write-Host "Ok" -ForegroundColor Green
}