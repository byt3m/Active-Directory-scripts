rem Author: https://github.com/byt3m
rem Description: Meant to launch the script "DNS_workstations_setup.ps1" via GPO
@echo off
rem pushd %~dp0
powershell.exe -WindowStyle Hidden -ExecutionPolicy RemoteSigned -file %~dp0\DNS_workstations_setup.ps1
rem pause