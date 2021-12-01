<#
Author: https://github.com/byt3m
Description: This is meant to be launched by a GPO. It will change the DNS server configuration of the affected computer objects.
#>

# Main vars
$PATH = "" # UNC path to a public share with modify permissions to write logs, example: \\some_server\public_dir
$dnsServers = @("ip1", "ip2") # DNS servers ip addresses to be applied

# Init logs
function GetCurrentDate() { return "[" + ([system.string](Get-Date).Year).trim() + ([system.string](Get-Date).Month).trim() + ([system.string](Get-Date).Day).trim() + " - " + ([system.string](Get-Date).Hour).trim() + ":" + ([system.string](Get-Date).Minute).trim() + ":" + ([system.string](Get-Date).Second).trim() + "]" }
function Log($text) { $date = GetCurrentDate; echo "$date $text" >> $global:log }
function LogError($text) { $date = GetCurrentDate; echo "$date $text" >> $global:errlog }
$global:log = Join-Path $PATH "DNS_workstations_setup\log_$env:COMPUTERNAME.txt"
$global:errlog = Join-Path $PATH "DNS_workstations_setup\err_log_$env:COMPUTERNAME.txt"
Log("Starting script")

# Setup DNS
Try 
{
    Log("Reading Interfaces")
    $interfaces = Get-DnsClientServerAddress

    Log("Configuring client DNS server address")
    $interfaces | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $dnsServers[0],$dnsServers[1] }

    Log("DONE")
}
Catch
{
    LogError("ERROR:")
    echo $Error[0] >> $errlog
}