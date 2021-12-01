<#
Author: https://github.com/byt3m
Description: This script will enable PowerShell Remote on a given computer. The certificate to be used by PSRemote will be created during the script execution, you will need a custom CA certificate.
#>

# Check admin rights
If (!(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”)))
{
    Write-Warning “Administrator privileges are required to run this script.”
    Exit
}

# Paths
$domain = "" # Domain, example: CONTOSO.LOCAL
$openssl = Join-Path $PSScriptRoot  "openssl\openssl.exe" # Openssl.exe bin
$caCrt = Join-Path $PSScriptRoot "" # CA .crt
$caKey = Join-Path $PSScriptRoot "" # CA .key
$pwdGenDLL = Join-Path $PSScriptRoot "PasswordGenerator.dll" # Password generator .NET lib
$exportPath = Join-Path $PSScriptRoot "exported_certificate" # Path to export PFX

# Openssl and extensions config
$requestCnf = ";----------------- request.inf -----------------`n`n[Version]`nSignature=`"$Windows NT$`n`n[NewRequest]`nSubject = `"CN=!COMPUTER_NAME!`"`nKeySpec = 1`nKeyLength = 4096`n; Can be 1024, 2048, 4096, 8192, or 16384.`n; Larger key sizes are more secure, but have`n; a greater impact on performance.`nExportable = TRUE`nMachineKeySet = TRUE`nSMIME = FALSE`nPrivateKeyArchive = FALSE`nUserProtected = FALSE`nUseExistingKeySet = FALSE`nProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"`nProviderType = 12`nRequestType = PKCS10`nKeyUsage = 0xa0`n`n[EnhancedKeyUsageExtension]`nOID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication`n[Extensions]`n2.5.29.17 = `"{text}`"`n_continue_ = `"dns=*.$domain&`"`n_continue_ = `"dns=$domain&`"`n_continue_ = `"dns=!COMPUTER_NAME!&`"`n`n;-----------------------------------------------`n"
$extCnf = "keyUsage=digitalSignature,keyEncipherment`nextendedKeyUsage=serverAuth`nsubjectKeyIdentifier=hash`nsubjectAltName = @alt_names`n[alt_names]`nDNS.1 = *.$domain`nDNS.2 = $domain`nDNS.3 = !COMPUTER_NAME!"

# Functions
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

    return $input
}


function Get-SecureStringPlaintext
{
    Param ( [securestring] $pwd )

    Try 
    {
       return $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
    }
    Catch
    {
        
        Write-Error "Secure string is empty!"
        exit
    }
}

function Get-RandomPassword
{
    [System.Reflection.Assembly]::LoadFrom($pwdGenDLL) | Out-Null
    return [PasswordGenerator.Generator]::getRandomPassword(12)
}
#

# Check vars not null
if ([System.String]::IsNullOrEmpty($openssl) -or  [System.String]::IsNullOrEmpty($caCrt) -or 
[System.String]::IsNullOrEmpty($caKey) -or [System.String]::IsNullOrEmpty($pwdGenDLL))
{
    Write-Host "Some required vars are null or empty" -ForegroundColor Cyan
    exit
}

# Check paths exist
if (!(Test-Path -Path $openssl) -or !(Test-Path -Path $caCrt) -or !(Test-Path -Path $caKey) -or !(Test-Path -Path $pwdGenDLL))
{
    Write-Error "Some of the required files do not exist!"
    exit
}

# Ask for caKey password
$caKeyFileName = [System.IO.Path]::GetFileName($caKey)
$caKeyPassword = ReadInput -msg "Specify the $caKeyFileName password" -secure

# Create certificate config files
write-host "[-] Creating configuration files" -ForegroundColor Cyan
$computerName = $env:COMPUTERNAME
$request = $requestCnf -replace "!COMPUTER_NAME!",$computerName
$requestPath = Join-Path $env:TEMP ($computerName + '.inf')
New-Item -Path $requestPath -ItemType File -Value $request -Force | Out-Null
$extensions = $extCnf -replace "!COMPUTER_NAME!",$computerName
$extensionsPath = Join-Path $env:TEMP ($computerName + '.ext')
New-Item -Path $extensionsPath -ItemType File -Value $extensions -Force | Out-Null

Start-Sleep -Seconds 1

# Create CSR
write-host "[-] Creating certificate request" -ForegroundColor Cyan
$csrPath = Join-Path $env:TEMP ($computerName + '.csr')
certreq -new $requestPath $csrPath

Start-Sleep -Seconds 1
    
# Create cert
write-host "[+] Creating certificate" -ForegroundColor Cyan
$crtPath = Join-Path $env:TEMP ($computerName + '.crt')
$param = "x509 -req -days 5475 -in `"$csrPath`" -CA `"$caCrt`" -CAkey `"$caKey`" -extfile `"$extensionsPath`" -set_serial 01 -passin pass:`""+(Get-SecureStringPlaintext -pwd $caKeyPassword)+"`" -out `"$crtPath`""
& $openssl ($param -split " ") 2> $null
    
# Accept cert
Write-Host "  [-] Accepting certificate" -ForegroundColor Cyan
certreq -accept $crtPath
    
# Export PFX
Write-Host "  [-] Exporting PFX" -ForegroundColor Cyan    
$pfxPassword = Get-RandomPassword
foreach ($l in ($pfxPassword -split "")) # if password contains quotes replace them with simple quotes.
{
    if ($l -eq '"')
    {
        $pfxPassword = $pfxPassword -replace '"', "'"
    }
}
$pfxPasswordPath = Join-Path $env:TEMP ($computerName + '.txt')
New-Item -Path $pfxPasswordPath -ItemType File -Value $pfxPassword -Force | Out-Null
$pfxPassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
    
$pfxPath = Join-Path $env:TEMP ($computerName + '.pfx')    
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN="+$computerName } | Export-PfxCertificate -FilePath "$pfxPath" -Password $pfxPassword | Out-Null
    
# Copy files
if (!(Test-Path -Path $exportPath)){ New-Item -Path $exportPath -ItemType Directory }
Copy-Item -Path $pfxPath -Destination $exportPath 
Copy-Item -Path $pfxPasswordPath -Destination $exportPath

# Clean temps
write-host "[-] Cleaning temporal files" -ForegroundColor Cyan
try
{
    Remove-Item -Path $requestPath -Force -ErrorAction Ignore
    Remove-Item -Path $extensionsPath -Force -ErrorAction Ignore
    Remove-Item -Path $csrPath -Force -ErrorAction Ignore
    Remove-Item -Path $crtPath -Force -ErrorAction Ignore
    Remove-Item -Path $pfxPath -Force -ErrorAction Ignore
    Remove-Item -Path $pfxPasswordPath -Force -ErrorAction Ignore
}
catch
{
    Write-Host "[X] Error deleting items from C:\Users\<user>\AppData\Local\Temp. Please DELETE manually all files with name $computerName." -ForegroundColor Red
}

# Enable PSRemote
write-host "[-] Enabling Powershell remote" -ForegroundColor Cyan
Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null

write-host "[-] Setting up HTTPS listener" -ForegroundColor Cyan
Remove-Item -Path WSMan:\localhost\Listener\* -Recurse -Force
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -Force -CertificateThumbPrint (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN="+$computerName }).Thumbprint | Out-Null

write-host "[-] Creating firewall rule" -ForegroundColor Cyan
Write-Warning "If creating the firewall rule gives an error, it can be due to the rule already existing, please manually check your firewall for a rule with name `"Windows Remote Management (HTTPS-In)`". If it does not exist, please create a rule that opens TCP port 5986 for inbound traffic."
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP -Direction Inbound -Action Allow | Out-Null

Write-Host "[*] Done!" -ForegroundColor Green