<#
Author: https://github.com/byt3m
Description: This script will change a DNS record of a given computer name.
#>

Clear-Host 

$ZoneName = "" # Domain name, example: CONTOSO.LOCAL

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

While ($True)
{
    Clear-Host

    # Ask for the computer name
    $ComputerName = ReadInput -msg "Enter the Computer Name"
    $DNSRecord = Get-DnsServerResourceRecord -ZoneName $ZoneName | Where-Object { $_.HostName -eq $ComputerName }

    if ($DNSRecord)
    {
        # Show DNS Entry
        Write-Host "`n`nFound the record!" -ForegroundColor Cyan
        Write-Host "_____________________________________________________________________________"
        $DNSRecord
        Write-Host "_____________________________________________________________________________`n`n"

        # Change DNS Entry
        $NewIPAddress = ReadInput -msg "Enter the NEW computer IP address"
        $NewDNSRecord = $DNSRecord.Clone()
        $NewDNSRecord.RecordData.IPv4Address = [System.Net.IPAddress]::parse($NewIPAddress)
        Set-DnsServerResourceRecord -NewInputObject $NewDNSRecord -OldInputObject $DNSRecord -ZoneName $ZoneName

        # Show new DNS entry configuration
        $new_results = Get-DnsServerResourceRecord -ZoneName $ZoneName | Where-Object { $_.HostName -eq $ComputerName }
        Write-Host "`n`nNew config:" -ForegroundColor Cyan
        Write-Host "______________________________________________________________________________"
        $new_results
        Write-Host "______________________________________________________________________________`n`n"
        Pause
    }
    else
    {
        Write-Host "No results found" -ForegroundColor Yellow
        Pause
    }
}