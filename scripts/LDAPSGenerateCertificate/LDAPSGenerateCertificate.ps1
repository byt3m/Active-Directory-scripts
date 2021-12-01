<#
Author: https://github.com/byt3m
Description: This script will generate the required certificates to enable LDAPS in an AD domain. The certificates are meant to be generated by a custom CA.
#>

Param
(
    [string]$csv,    
    [string]$outputDir
)

# Paths (for release)
$domain # Domain, example: CONTOSO.LOCAL
$countryCode = "" # Country code to create the certificate, example for Spain: ES.
$street = "" # Street address for the certificate
$organitzation = "" # Organization in charge of the certificate, example: CONTOSO
$openssl = Join-Path $PSScriptRoot  "openssl\openssl.exe" # Openssl.exe bin
$opensslCnf = Join-Path $PSScriptRoot  "openssl\openssl.cnf" # Openssl.cnf config
$caCrt = Join-Path $PSScriptRoot "" # CA .crt
$caKey = Join-Path $PSScriptRoot "" # CA .key
$pwdGenDLL = Join-Path $PSScriptRoot "PasswordGenerator.dll" # Password generator .NET lib

# Openssl and extensions config
$opensslCnfAddition = "[SAN]`nsubjectAltName=DNS:!COMPUTER_NAME!,DNS:*.$domain,DNS:$domain"
$extCnf = "subjectAltName = @alt_names`n[alt_names]`nDNS.1 = !COMPUTER_NAME!`nDNS.2 = *.$domain`nDNS.3 = $domain"

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
if ([System.String]::IsNullOrEmpty($openssl) -or [System.String]::IsNullOrEmpty($opensslCnf) -or 
[System.String]::IsNullOrEmpty($csv) -or [System.String]::IsNullOrEmpty($caCrt) -or 
[System.String]::IsNullOrEmpty($caKey) -or [System.String]::IsNullOrEmpty($pwdGenDLL) -or 
[System.String]::IsNullOrEmpty($outputDir))
{
    Write-Host "`nUsage: .\batchGenerateCerts.ps1 <info_csv> <output_dir>" -ForegroundColor Cyan
    Write-Host "`tinfo_csv    -> CSV containing with the required information to generate the certificates. Format is `"computer name;operating system`" and has no headers." -ForegroundColor Cyan
    Write-Host "`toutputDir   -> Output directory for certs.`n" -ForegroundColor Cyan
    exit
}

# Check paths exist
if (!(Test-Path -Path $openssl) -or !(Test-Path -Path $opensslCnf) -or !(Test-Path -Path $csv) -or !(Test-Path -Path $caCrt) -or !(Test-Path -Path $caKey) -or !(Test-Path -Path $pwdGenDLL) -or !(Test-Path -Path $outputDir))
{
    Write-Error "Some of the required files do not exist!"
    exit
}

# Check csv file is not empty
$csvContent = Get-Content -Path $csv -Force
if (!$csvContent)
{
    Write-Error "CSV file is empty!"
    exit
}

# Check openssl config file content
$opensslCnfContent = Get-Content -Path $opensslCnf -Force
if (!$opensslCnfContent)
{
    Write-Error "Openssl config file is empty!"
    exit
}

# Ask for caKey password
$caKeyFileName = [System.IO.Path]::GetFileName($caKey)
$caKeyPassword = ReadInput -msg "Specify the $caKeyFileName password" -secure

# Create certificates
foreach ($item in $csvContent)
{
    # Get item info
    $computerName = ($item -split ";")[0].trim()

    Write-Host "[+] Creating certificates for $computerName" -ForegroundColor Cyan

    # Create config files
    $config = ($opensslCnfContent + "`n" + ($opensslCnfAddition -replace "!COMPUTER_NAME!",$computerName)) | Out-String
    $configPath = Join-Path $env:TEMP ($computerName + '.cnf')
    New-Item -Path $configPath -ItemType File -Value $config -Force | Out-Null
    $extensions = $extCnf -replace "!COMPUTER_NAME!",$computerName
    $extensionsPath = Join-Path $env:TEMP ($computerName + '.ext')
    New-Item -Path $extensionsPath -ItemType File -Value $extensions -Force | Out-Null
    
    Start-Sleep -Seconds 1

    # Create CSR
    $csrPath = Join-Path $env:TEMP ($computerName + '.csr')
    $keyPath = Join-Path $env:TEMP ($computerName + '.key')
    $param = "req -new -nodes -sha256 -out `"$csrPath`" -newkey rsa:2048 -keyout `"$keyPath`" -extensions v3_req -subj `"/C=$countryCode/ST=$street/O=$organitzation/CN=$domain`" -reqexts SAN -config `"$configPath`""
    & $openssl ($param -split " ") 2> $null

    Start-Sleep -Seconds 1
    
    # Create cert
    $crtPath = Join-Path $env:TEMP ($computerName + '.crt')
    $param = "x509 -req -days 5475 -sha256 -extfile `"$extensionsPath`" -in `"$csrPath`" -CA `"$caCrt`" -CAkey `"$caKey`" -passin pass:`""+(Get-SecureStringPlaintext -pwd $caKeyPassword)+"`" -CAcreateserial -out `"$crtPath`""
    & $openssl ($param -split " ") 2> $null

    $pfxPath = Join-Path $env:TEMP ($computerName + '.pfx')
    $pwdPath = Join-Path $env:TEMP ($computerName + '.txt')
    $pwd = Get-RandomPassword
    New-Item -Path $pwdPath -ItemType File -Value $pwd -Force | Out-Null
    $param = "pkcs12 -export -out `"$pfxPath`" -inkey `"$keyPath`" -in `"$crtPath`" -passout pass:`"$pwd`""
    & $openssl ($param -split " ") #2> $null

    # Copy items
    try
    {
         Copy-Item -Path $pfxPath -Destination $outputDir -Force -ErrorAction Ignore
         Copy-Item -Path $pwdPath -Destination $outputDir -Force -ErrorAction Ignore
    }
    catch
    {
        Write-Error "Error copying items from C:\Users\<user>\AppData\Local\Temp to output dir"
    }

    # Clean
    try
    {
        Remove-Item -Path $configPath -Force -ErrorAction Ignore
        Remove-Item -Path $extensionsPath -Force -ErrorAction Ignore
        Remove-Item -Path $csrPath -Force -ErrorAction Ignore
        Remove-Item -Path $crtPath -Force -ErrorAction Ignore
        Remove-Item -Path $keyPath -Force -ErrorAction Ignore
        Remove-Item -Path $pfxPath -Force -ErrorAction Ignore
        Remove-Item -Path $pwdPath -Force -ErrorAction Ignore
    }
    catch
    {
        Write-Error "Error deleting items from C:\Users\<user>\AppData\Local\Temp, certs and keys are probably still there!"
    }
}