<#
Author: https://github.com/byt3m
Description: This script will perform several security checks in an AD domain.
#>

Clear-Host 


# Global variables

$domain_fqdn = "" # Domain, example: CONTOSO.LOCAL
$inactive_computers_days = "180"
$inactive_computers_white_list_path = Join-Path $PSScriptRoot "white_list_inactive_computers.txt"
$inactive_users_days = "180"
$inactive_users_white_list_path = Join-Path $PSScriptRoot "white_list_inactive_users.txt"
$krbtgt_days = "180"
$DSRM_days = "180"

$today = Get-Date -format "yyyyMMdd"
$files_dir = Join-Path $PSScriptRoot $today
$summary = @()
$summary_csv_name = $today + "_SUMMARY.csv"
$summary_csv_path = Join-Path $files_dir $summary_csv_name


# Admin check 

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Host "Run the script as administrator" -ForegroundColor Red
	Exit
}


# Intro message

Write-Host "This script makes the following checks:" -ForegroundColor Yellow
write-host "`t- Computers  that are inactive for more than $inactive_computers_days days." -ForegroundColor Yellow
write-host "`t- Users that are inactive for more than $inactive_users_days days." -ForegroundColor Yellow
write-host "`t- Users with passwords that never expires." -ForegroundColor Yellow
write-host "`t- Users with SPNs (Service Principal Names)." -ForegroundColor Yellow
write-host "`t- Users with the attribute `"Disable Kerberos Pre-Authentication (DoesNotRequirePreAuth)`" enabled." -ForegroundColor Yellow
write-host "`t- Users with the attribute `"PasswordNotRequired`" enabled." -ForegroundColor Yellow
write-host "`t- Users with the attribute `"AllowReversiblePasswordEncryption`" enabled." -ForegroundColor Yellow
write-host "`t- Users with the attribute `"AdminCount`" and a value of 1." -ForegroundColor Yellow
write-host "`t- krbtgt's account keys last reset is more than $krbtgt_days old." -ForegroundColor Yellow
write-host "`t- Owner of the DCs is the group `"BUILTIN\Domain Admins.`"" -ForegroundColor Yellow
write-host "`t- Tier 0 Admin users are in group `"Protected Users`" and cannot be delegated." -ForegroundColor Yellow
write-host "`t- Password of accounts BUILTIN\Administrator, BUILTIN\Guest and DSRM are not expired nor last reset was more than $DSRM_days days." -ForegroundColor Yellow
write-host "`t- [TODO] Correct GPO permissions." -ForegroundColor Yellow
Pause

# Files dir check

if (!(Test-Path -Path $files_dir))
{
    New-Item -Path $files_dir -ItemType Directory | Out-Null
}
else
{
    Write-Host "Directory `"$files_dir`" already exists!" -ForegroundColor Red
    Exit
}


# Inactive Computers

$inactive_computers_csv_name = $today + "_inactive_computers.csv"
$inactive_computers_csv_path = Join-Path $files_dir $inactive_computers_csv_name

Write-Host "`n[+] Checking for inactive computers..." -ForegroundColor Cyan

$inactive_computers_days += ".00:00:00"

if (Test-Path -Path $inactive_computers_white_list_path)
{
    Write-Host "  [!] Using whitelist `"$inactive_computers_white_list_path`"." -ForegroundColor Yellow
    $inactive_computers_white_list = Get-Content $inactive_computers_white_list_path
    $inactive_computers = Search-ADaccount -ComputersOnly -AccountInactive -Timespan $inactive_computers_days | `
        where-object { $domain$_.Name -notin $inactive_computers_white_list -and $_.LastLogonDate } | `
            Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, Enabled
}
else
{
    Write-Host "  [!] Whitelist `"$inactive_computers_white_list`" not found, results will not be filtered." -ForegroundColor Yellow
    $inactive_computers = Search-ADaccount -ComputersOnly -AccountInactive -Timespan $inactive_computers_days | `
        where-object { $domain$_.LastLogonDate } | `
            Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, Enabled
}

if ($inactive_computers)
{
    $inactive_computers_csv_name = $today + "_inactive_computers.csv"
    $inactive_computers_csv_path = Join-Path $files_dir $inactive_computers_csv_name
    Write-Host "  [X] Found inactive computers, saving file `"$inactive_computers_csv_path`"" -ForegroundColor Red
    $inactive_computers | Export-Csv -Path $inactive_computers_csv_path -Delimiter ";" -NoTypeInformation    
    $summary += [PSCustomObject]@{
        Name = "Inactive computers"
        Check = "FAIL"
        Comments = "Found inactive computers"
    }
}
else
{
    Write-Host "  [*] No inactive computers found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "Inactive computers"
        Check = "PASS"
        Comments = "No inactive computers found"
    }
}


# Inactive Users

Write-Host "`n[+] Checking for inactive users..." -ForegroundColor Cyan

$inactive_users_days += ".00:00:00"

if (Test-Path -Path $inactive_users_white_list_path)
{
    Write-Host "  [!] Using whitelist `"$inactive_users_white_list_path`"." -ForegroundColor Yellow
    $inactive_users_white_list = Get-Content $inactive_users_white_list_path
    $inactive_users = Search-ADaccount -UsersOnly -AccountInactive -Timespan $inactive_users_days | `
        where-object { $domain$_.SamAccountName -notin $inactive_users_white_list -and $_.LastLogonDate } | `
            Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, Enabled
}
else
{
    Write-Host "  [!] Whitelist `"$inactive_users_white_list_path`" not found, results will not be filtered." -ForegroundColor Yellow
    $inactive_users = Search-ADaccount -UsersOnly -AccountInactive -Timespan $inactive_users_days | `
        where-object { $domain$_.LastLogonDate } | `
            Select-Object Name, SamAccountName, DistinguishedName, LastLogonDate, Enabled
}



if ($inactive_users)
{
    $inactive_users_csv_name = $today + "_inactive_users.csv"
    $inactive_users_csv_path = Join-Path $files_dir $inactive_users_csv_name
    Write-Host "  [X] Found inactive users, saving file `"$inactive_users_csv_path`"" -ForegroundColor Red
    $inactive_users | Export-Csv -Path $inactive_users_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "Inactive users"
        Check = "FAIL"
        Comments = "Found inactive users"
    }
}
else
{
    Write-Host "  [*] No inactive users found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "Inactive users"
        Check = "PASS"
        Comments = "No inactive users found"
    }
}


# Users with passwords that never expire

Write-Host "`n[+] Checking for users with passwords that never expire..." -ForegroundColor Cyan

$password_never_expires_users = Get-ADUser -filter { userprincipalname -like "*" } -Property PasswordNeverExpires | `
                                    Where-Object { $_.PasswordNeverExpires -eq $True $domain } | `
                                        Select-Object Name, SamAccountName, DistinguishedName, PasswordNeverExpires, Enabled


if ($password_never_expires_users)
{
    $password_never_expires_users_csv_name = $today + "_PasswordNeverExpires_users.csv"
    $password_never_expires_users_csv_path = Join-Path $files_dir $password_never_expires_users_csv_name
    Write-Host "  [X] Found  users with passwords that never expire, saving file `"$password_never_expires_users_csv_path`"" -ForegroundColor Red
    $password_never_expires_users | Export-Csv -Path $password_never_expires_users_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "Password never expire users"
        Check = "FAIL"
        Comments = "There are users with passwords that never expire"
    }
}
else
{
    Write-Host "  [*] No users with passwords that never expire found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "Password never expire users"
        Check = "PASS"
        Comments = "No users with password that never expire"
    }
}


# SPNs

Write-Host "`n[+] Checking for users with SPNs..." -ForegroundColor Cyan

$users_with_spns = Get-ADUser -filter { serviceprincipalname -like "*" } -Properties serviceprincipalname | `
                        Where-Object { $_.SamAccountName -ne "krbtgt" }

if ($users_with_spns)
{
    $users_with_spns_csv_name = $today + "_spn_users.csv"
    $users_with_spns_csv_path = Join-Path $files_dir $users_with_spns_csv_name
    Write-Host "  [!] Found  users with SPNs, saving file `"$users_with_spns_csv_path`"" -ForegroundColor Yellow
    $users_with_spns | Select-Object Name, SamAccountName, DistinguishedName, `
                        @{name=”serviceprincipalname”;expression={$_.serviceprincipalname -join “`n”}}, Enabled | `
                            Export-Csv -Path $users_with_spns_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "SPN users"
        Check = "WARNING"
        Comments = "There are users with SPNs, make sure they are service accounts."
    }
}
else
{
    Write-Host "  [*] No users with SPNs found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "SPN users"
        Check = "PASS"
        Comments = "No users with SPNs found"
    }
}


# Disabled Kerberos Pre-Authentication

Write-Host "`n[+] Checking for users with `"Disable Kerberos Pre-Authentication (DoesNotRequirePreAuth)`" enabled..." -ForegroundColor Cyan

$users_with_dkpreauth = Get-ADUser -Filter { userprincipalname -like "*" } -Properties DoesNotRequirePreAuth | `
                            Where-Object { $_.DoesNotRequirePreAuth -eq $True } | `
                                Select-Object Name, SamAccountName, DistinguishedName, DoesNotRequirePreAuth, Enabled

if ($users_with_dkpreauth)
{
    $users_with_dkpreauth_csv_name = $today + "_DoesNotRequirePreAuth_users.csv"
    $users_with_dkpreauth_csv_path = Join-Path $files_dir $users_with_dkpreauth_csv_name
    Write-Host "  [X] Found  users with `"Disable Kerberos Pre-Authentication`", saving file `"$users_with_dkpreauth_csv_path`"" -ForegroundColor Red
    $users_with_dkpreauth | Export-Csv -Path $users_with_dkpreauth_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "DoesNotRequirePreAuth users"
        Check = "FAIL"
        Comments = "There are users that do not require kerberos pre-authentication."
    }
}
else
{
    Write-Host "  [*] No users with `"Disable Kerberos Pre-Authentication`" enabled found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "DoesNotRequirePreAuth users"
        Check = "PASS"
        Comments = "There are no users with the flag DoesNotRequirePreAuth."
    }
}


# PasswordNotRequired

Write-Host "`n[+] Checking for users with `"PasswordNotRequired`" enabled..." -ForegroundColor Cyan

$users_with_pswntreqrd = Get-ADUser -Filter { userprincipalname -like "*" } -Properties PasswordNotRequired | `
                            Where-Object { $_.PasswordNotRequired -eq $True } | `
                                Select-Object Name, SamAccountName, DistinguishedName, PasswordNotRequired, Enabled

if ($users_with_pswntreqrd)
{
    $users_with_pswntreqrd_csv_name = $today + "_PasswordNotRequired_users.csv"
    $users_with_pswntreqrd_csv_path = Join-Path $files_dir $users_with_pswntreqrd_csv_name
    Write-Host "  [X] Found  users with `"PasswordNotRequired`", saving file `"$users_with_pswntreqrd_csv_path`"" -ForegroundColor Red
    $users_with_pswntreqrd | Export-Csv -Path $users_with_pswntreqrd_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "PasswordNotRequired users"
        Check = "FAIL"
        Comments = "There are users that do not require password."
    }
}
else
{
    Write-Host "  [*] No users with `"PasswordNotRequired`" enabled found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "PasswordNotRequired users"
        Check = "PASS"
        Comments = "There are no users with the flag PasswordNotRequired."
    }
}


# AllowReversiblePasswordEncryption

Write-Host "`n[+] Checking for users with `"AllowReversiblePasswordEncryption`" enabled..." -ForegroundColor Cyan

$users_with_allrevpswenc = Get-ADUser -Filter { userprincipalname -like "*" } -Properties AllowReversiblePasswordEncryption | `
                            Where-Object { $_.AllowReversiblePasswordEncryption -eq $True } | `
                                Select-Object Name, SamAccountName, DistinguishedName, AllowReversiblePasswordEncryption, Enabled

if ($users_with_allrevpswenc)
{
    $users_with_allrevpswenc_csv_name = $today + "_AllowReversiblePasswordEncryption_users.csv"
    $users_with_allrevpswenc_csv_path = Join-Path $files_dir $users_with_allrevpswenc_csv_name
    Write-Host "  [X] Found  users with `"AllowReversiblePasswordEncryption`", saving file `"$users_with_allrevpswenc_csv_path`"" -ForegroundColor Red
    $users_with_allrevpswenc | Export-Csv -Path $users_with_allrevpswenc_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "AllowReversiblePasswordEncryption users"
        Check = "FAIL"
        Comments = "There are users with password that can be deciphered."
    }
}
else
{
    Write-Host "  [*] No users with `"AllowReversiblePasswordEncryption`" enabled found." -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "AllowReversiblePasswordEncryption users"
        Check = "PASS"
        Comments = "There are no users with the flag AllowReversiblePasswordEncryption."
    }
}


# AdminCount = 1

Write-Host "`n[+] Checking for users with `"AdminCount=1`"..." -ForegroundColor Cyan

$users_with_admincount = Get-ADUser -Filter { userprincipalname -like "*" } -Properties admincount | `
                            Where-Object { $_.admincount -eq "1" } | `
                                Select-Object Name, SamAccountName, DistinguishedName, admincount, Enabled

if ($users_with_admincount)
{
    $users_with_admincount_csv_name = $today + "_admincount_users.csv"
    $users_with_admincount_csv_path = Join-Path $files_dir $users_with_admincount_csv_name
    Write-Host "  [!] Found  users with `"AdminCount=1`", saving file `"$users_with_admincount_csv_path`"" -ForegroundColor Yellow
    $users_with_admincount | Export-Csv -Path $users_with_admincount_csv_path -Delimiter ";" -NoTypeInformation
    $summary += [PSCustomObject]@{
        Name = "Admincount users"
        Check = "WARNING"
        Comments = "There are users with the flag Admincount. Make sure they are real admin users."
    }
}
else
{
    Write-Host "  [*] No users with `"AdminCount=1`" found!" -ForegroundColor Red
    $summary += [PSCustomObject]@{
        Name = "Admincount users"
        Check = "WARNING"
        Comments = "There are no users with the flag Admincount. There must be at least one account with this flag. For example, the domain BUILTIN\Administrador."
    }
}

# krbtgt account keys reset

Write-Host "`n[+] Checking if the krbtgt keys last reset is more than $krbtgt_days old..." -ForegroundColor Cyan

$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
$krbtgt_reset_date = [DateTime]$krbtgt.PasswordLastSet.toString("MM/dd/yyyy")
$krbtgt_today = [DateTime](Get-Date -format MM/dd/yyyy)
$krbtgt_days_since_reset = ($krbtgt_today - $krbtgt_reset_date).TotalDays

if ($krbtgt_days_since_reset -ge $krbtgt_days)
{
    Write-Host "  [X] Account keys are $krbtgt_days_since_reset days old (less than $krbtgt_days). Needs to be reset!" -ForegroundColor Red
    $summary += [PSCustomObject]@{
        Name = "krbtgt reset"
        Check = "FAIL"
        Comments = "Account keys are $krbtgt_days_since_reset days old (less than $krbtgt_days). The keys must be reset."
    }
}
else
{
    Write-Host "  [*] Account keys are $krbtgt_days_since_reset days old (less than $krbtgt_days). Does not need to be reset" -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "krbtgt reset"
        Check = "PASS"
        Comments = "Account keys are $krbtgt_days_since_reset days old (less than $krbtgt_days). The keys do not need to be reset."
    }
}


# DCs owners

Write-Host "`n[+] Checking Domain Controller Owners..." -ForegroundColor Cyan

$dc_owners = Get-ADComputer -Server $domain_fqdn -LDAPFilter "(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))" -Properties name, ntsecuritydescriptor | Select-Object name,{$_.ntsecuritydescriptor.Owner}
$domain = Get-ADDomain $domain_fqdn
$domain_admins_sid = $domain.DomainSID.Value.trim() + "-512"

foreach ($owner in $dc_owners)
{
    try
    { 
        $global:group = Get-ADGroup ($owner.'$_.ntsecuritydescriptor.Owner'.trim() -split "\\")[1]
    }
    Catch
    {
        $global:group = Get-ADUser ($owner.'$_.ntsecuritydescriptor.Owner'.trim() -split "\\")[1]
    }

    $dc_name = $owner.name.Trim()

    if ($group.SID.Value.trim() -eq $domain_admins_sid)
    {
        Write-Host "  [*] Domain admins group is the owner of the DC $dc_name" -ForegroundColor Green
        $summary += [PSCustomObject]@{
            Name = "Domain Controller owners"
            Check = "PASS"
            Comments = "Domain admins group is the owner of the DC $dc_name"
        }
    }
    else
    {
        Write-Host "  [X] Domain admins group is NOT the owner of the DC $dc_name!" -ForegroundColor Red
        $summary += [PSCustomObject]@{
            Name = "Domain Controller owners"
            Check = "FAIL"
            Comments = "Domain admins group is NOT the owner of the DC $dc_name"
        }
    }
}


# Tier 0 Admin Users

Write-Host "`n[+] Checking Tier 0 Admin users..." -ForegroundColor Cyan

$domain = Get-ADDomain $domain_fqdn
$domain_admins_sid = $domain.DomainSID.Value.trim() + "-512"
$schema_admins_SID = $domain.DomainSID.Value.trim() + "-518"
$enterprise_admins_SID = $domain.DomainSID.Value.trim() + "-519"
$protected_users_SID = $domain.DomainSID.Value.trim() + "-525"


$SIDs = @($domain_admins_sid, $schema_admins_SID, $enterprise_admins_SID)
$Tier0_Admins = @()

Get-ADGroupMember "Tier 0" | foreach { 

    $SamAccountName = $_.SamAccountName
    $distinguishedName = $_.distinguishedName

    Get-ADPrincipalGroupMembership $_.SamAccountName | foreach {

        if ($_.SID -in $SIDs -and $distinguishedName -notmatch "Service Accounts" -and $SamAccountName -notin $Tier0_Admins)
        {
            $Tier0_Admins += $SamAccountName
        }

    }
}

$without_protected_users_group = @()
$without_account_not_delegated = @()

foreach ($user in $Tier0_Admins)
{
    # Check protected users group membership
    $has_protected_users_group = $false

    Get-ADPrincipalGroupMembership $user | foreach {
    
        if ($_.SID -eq $protected_users_SID)
        {
            $has_protected_users_group = $true
        }

    }

    if (!$has_protected_users_group)
    {
        $without_protected_users_group += $user
    }

    # Check cannot delegate attribute
    $user_properties = Get-ADUser $user -Properties "AccountNotDelegated"
    if (!$user_properties.AccountNotDelegated)
    {
        $without_account_not_delegated += $user
    }
}

if ($without_protected_users_group)
{
    Write-Host "  [X] Found Tier 0 Admins that are not in Protected Users group. Check Summary for more information." -ForegroundColor Red
    $tmp = $without_protected_users_group -join ", "
    $summary += [PSCustomObject]@{
        Name = "Tier 0 Admins - Protected Users group"
        Check = "FAIL"
        Comments = "Tier 0 Admins that are not in Protected Users group: $tmp"
    }
}
else
{
    $summary += [PSCustomObject]@{
        Name = "Tier 0 Admins - Protected Users group"
        Check = "PASS"
        Comments = ""
    }
}

if ($without_account_not_delegated)
{
    Write-Host "  [X] Found Tier 0 Admins that can be delegated. Check Summary for more information." -ForegroundColor Red
    $tmp = $without_account_not_delegated -join ", "
    $summary += [PSCustomObject]@{
        Name = "Tier 0 Admins - AccountBeDelegated"
        Check = "FAIL"
        Comments = "Tier 0 Admins that can be delegated: $tmp"
    }
}
else
{
    $summary += [PSCustomObject]@{
        Name = "Tier 0 Admins - AccountBeDelegated"
        Check = "PASS"
        Comments = ""
    }
}



# Old passwords

Write-Host "`n[+] Checking Administrator and Guest accounts..." -ForegroundColor Cyan

$domain = Get-ADDomain $domain_fqdn
$administrator_SID = $domain.DomainSID.Value.trim() + "-500"
$guest_SID = $domain.DomainSID.Value.trim() + "-501"

# Check Administrator
$administrator = get-aduser -Filter { SID -like "*" } -Properties "PasswordLastSet" | Where-Object { $_.SID -eq $administrator_SID }
$administrator_password_reset_date = [DateTime]$administrator.PasswordLastSet.toString("MM/dd/yyyy")
$administrator_today = [DateTime](Get-Date -format MM/dd/yyyy)
$administrator_days_since_reset = ($administrator_today - $administrator_password_reset_date).TotalDays

if ($administrator_days_since_reset -ge $DSRM_days)
{
    Write-Host "  [X] BUILTIN\Administrator password is more than $DSRM_days days old!" -ForegroundColor Red
    Write-Host "  [!] DSRM password is probably outdated too!" -ForegroundColor Yellow
    $summary += [PSCustomObject]@{
        Name = "BUILTIN\Administrator password time"
        Check = "FAIL"
        Comments = "Password must be changed. DSRM password is probably outdated too!"
    }
}
else
{
    Write-Host "  [*]  BUILTIN\Administrator password is $administrator_days_since_reset days old (less than $DSRM_days)" -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "BUILTIN\Administrator password time"
        Check = "PASS"
        Comments = "Password is $administrator_days_since_reset days old (less than $DSRM_days)"
    }
}

# Check Guest
$guest = get-aduser -Filter { SID -like "*" } -Properties "PasswordLastSet" | Where-Object { $_.SID -eq $guest_SID }
$guest_password_reset_date = [DateTime]$guest.PasswordLastSet.toString("MM/dd/yyyy")
$guest_today = [DateTime](Get-Date -format MM/dd/yyyy)
$guest_days_since_reset = ($guest_today - $guest_password_reset_date).TotalDays

if ($guest_days_since_reset -ge $DSRM_days)
{
    Write-Host "  [X] BUILTIN\Guest password is more than $DSRM_days days old!" -ForegroundColor Red
    Write-Host "  [!] DSRM password is probably outdated too!" -ForegroundColor Yellow
    $summary += [PSCustomObject]@{
        Name = "BUILTIN\Guest password time"
        Check = "FAIL"
        Comments = "Password must be changed. DSRM password is probably outdated too!"
    }
}
else
{
    Write-Host "  [*]  BUILTIN\Guest password is $guest_days_since_reset days old (less than $DSRM_days)" -ForegroundColor Green
    $summary += [PSCustomObject]@{
        Name = "BUILTIN\Guest password time"
        Check = "PASS"
        Comments = "Password is $guest_days_since_reset days old (less than $DSRM_days)"
    }
}



# Export summary
Write-Host "`n`n[-] Checks finished, exporting summary to `"$summary_csv_path`"" -ForegroundColor Cyan
$summary | Export-Csv -Path $summary_csv_path -Delimiter ";" -NoTypeInformation