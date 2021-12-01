<#
Author: https://github.com/byt3m
Description: This script will create the necessary OUs to start applying the Tier administrative model (https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model)
#>

Clear-Host

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Host "Run the script as administrator" -ForegroundColor Red
	Exit
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

$FQDN = ReadInput -msg "Enter the FQDN of the domain (example: CONTOSO.LOCAL)"

$FQDN_splitted = $FQDN.Split(".")

$domain_root_array = @()

for ($i = 0; $i -lt $FQDN_splitted.Length; $i++)
{
    $domain_root_array += "DC="+$FQDN_splitted[$i]
}

$domain_root = $domain_root_array -join ","

# OUs

Write-Host "Creating OUs" -ForegroundColor Yellow

New-ADOrganizationalUnit -Name "ADMIN" -Path "$domain_root"

New-ADOrganizationalUnit -Name "Tier 0" -Path "OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Tier 1" -Path "OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Tier 2" -Path "OU=ADMIN,$domain_root"

New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 0,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 0,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 0,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 0,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier 0,OU=ADMIN,$domain_root"

New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 1,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 1,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 1,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 1,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier 1,OU=ADMIN,$domain_root"

New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 2,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Devices" -Path "OU=Tier 2,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 2,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=Tier 2,OU=ADMIN,$domain_root"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Tier 2,OU=ADMIN,$domain_root"


# GROUPS

New-ADGroup -Name "Tier 0" -Path "OU=Groups,OU=Tier 0,OU=ADMIN,$domain_root" -GroupScope Global
New-ADGroup -Name "Tier 1" -Path "OU=Groups,OU=Tier 1,OU=ADMIN,$domain_root" -GroupScope Global
New-ADGroup -Name "Tier 2" -Path "OU=Groups,OU=Tier 2,OU=ADMIN,$domain_root" -GroupScope Global


Write-Host "Finished" -ForegroundColor Green