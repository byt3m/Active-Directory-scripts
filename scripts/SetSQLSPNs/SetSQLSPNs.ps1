<#
Author: https://github.com/byt3m
Description: This script will setup the required SPNs for MSSQL servers to work with AD authentication
#>

Clear-Host 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Host "Run the script as administrator" -ForegroundColor Red
	Exit
}

function CheckADUser
{
    Param ( [string] $user ) 
    Try { Get-ADUser $user; return $true }
    Catch { return $false }
}

function CheckADDomain
{
    Param ( [string] $domain ) 
    Try { Get-ADDomain $domain; return $true }
    Catch { return $false }
}

function CheckADComputer
{
    Param ( [string] $computer ) 
    Try { Get-ADComputer $computer; return $true }
    Catch { return $false }
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


$config_file = Join-Path -Path $PSScriptRoot "config.xml"
[xml]$config = Get-Content $config_file

$domain_FQDN = $config.config.domain_fqdn
$MSSQL_port = $config.config.mssql_port
$service_account = $config.config.service_account_name


if (!(CheckADDomain -domain $domain_FQDN))
{
    Write-Host "Domain `"$domain_FQDN`" does not exist." -ForegroundColor Red
    Exit
}

if (!(CheckADUser -user $service_account))
{
    Write-Host "Service account `"$service_account`" does not exist." -ForegroundColor Red
    Exit
}


Write-Host "Choose the script operation mode:`n`t1. Manually enter server names.`n`t2. Read server names from txt file (one server name per line).`n`t3. Exit`n" -ForegroundColor Cyan

While ($true)
{
    $mode = ReadInput -msg "Operation mode"

    if ($mode -eq "1")
    {
        $operation_manual = Join-Path -Path $PSScriptRoot "SetSQLSPNs_manual.ps1"
        . $operation_manual
        break
    }
    elseif ($mode -eq "2")
    {
        $operation_auto = Join-Path -Path $PSScriptRoot "SetSQLSPNs_auto.ps1"
        . $operation_auto
        break
    }
    elseif ($mode -eq "3")
    {
        exit
    }
    else
    {
        Write-Host "Invalid answer" -ForegroundColor Red
    }
}