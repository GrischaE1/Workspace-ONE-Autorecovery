<#
.SYNOPSIS
    Automates the re-enrollment process for devices in the Workspace ONE UEM environment.

.DESCRIPTION
    The UEM_automatic_reenrollment.ps1 script is designed to automatically re-enroll devices that have become non-compliant or have lost their management profiles in the Workspace ONE UEM environment.
    It identifies affected devices and initiates the necessary re-enrollment procedures to restore their compliance with the established management policies.
    This script is intended to be integrated into an automated recovery workflow or executed on-demand as part of remediation efforts.

.PARAMETERS
    None

.EXAMPLE
    PS> .\UEM_automatic_reenrollment.ps1
    Executes the re-enrollment process, scanning for non-compliant devices and enrolling them back into the Workspace ONE environment.
    It is recommended to incorporate this script into your scheduled remediation tasks for continuous device compliance.

.NOTES
    Author       : Grischa Ernst
    Date         : 2025-08-29
    Version      : 1.1.0
    Requirements : 
                      - PowerShell 5.1 or later / PowerShell Core 7+
                      - Access to Workspace ONE UEM endpoints
                      - Properly configured credentials and environment settings
    Purpose      : To ensure continuous device management by automatically re-enrolling devices that have fallen out of compliance.
    Dependencies : Relies on Workspace ONE UEM API endpoints and supporting configuration settings.
    Execution    : Intended to be run as part of an automated remediation workflow or manually when needed.

.LICENSE
    Distributed under the terms specified in the license.md file.
#>



add-type -AssemblyName System.Web
$Password = [System.Web.Security.Membership]::GeneratePassword(16, 4) 
$EncryptedPassword = $Password |  ConvertTo-SecureString -AsPlainText -Force

#Check if the local user already is created, if not, create the user
if (!(Get-LocalUser | Where-Object { $_.Name -eq "UEMEnrollment" } -ErrorAction SilentlyContinue)) {

    $NewUserData = @{
        Name                     = "UEMEnrollment"
        Password                 = $EncryptedPassword
        FullName                 = "UEM Enrollment Account"
        Description              = "Do NOT delete this account"
        AccountNeverExpires      = $true
        PasswordNeverExpires     = $true
        UserMayNotChangePassword = $true
    }
    
    New-LocalUser @NewUserData
    
    $LocalAdminGroup = Get-LocalGroup | Where-Object { $_.name -like "admin*" }
    Enable-LocalUser -Name "UEMEnrollment"
    Add-LocalGroupMember -Group $LocalAdminGroup -Member "UEMEnrollment"
}
else {
    Set-LocalUser -Name "UEMEnrollment" -Password $EncryptedPassword
    Enable-LocalUser -Name "UEMEnrollment"
    $LocalAdminGroup = Get-LocalGroup | Where-Object { $_.name -like "admin*" }
    Add-LocalGroupMember -Group $LocalAdminGroup -Member "UEMEnrollment"
}

#Confogure Autologon for the "installer" user
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "UEMEnrollment" -type String 
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$($Password)" -type String
Set-ItemProperty $RegistryPath 'EnableFirstLogonAnimation' -Value "0" -Type String
Set-ItemProperty $RegistryPath 'DefaultDomain' -Value "$($env:computername)" -Type String

#Skip user prompts after login
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f

#Register the scheduled task to run the Workspace ONE enrollment after the device is rebooted and logged in as "Installer"
schtasks.exe /create /tn "WorkspaceONE Enrollment" /ru "UEMEnrollment" /rp "$($Password)" /sc ONLOGON /tr "powershell -executionpolicy bypass -file C:\Windows\UEMRecovery\recovery.ps1" /IT /F

#Create a scheduled task to trigger the screen lock during the autologon 
$action = New-ScheduledTaskAction -Execute "rundll32.exe" -Argument "user32.dll,LockWorkStation"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "UEMEnrollment"
$principal = New-ScheduledTaskPrincipal -UserId "UEMEnrollment" -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Register-ScheduledTask -TaskName "Screenlock" -InputObject $task -Force



#Trigger restart to restart into the autologon 
$shutdown = "/r /t 20 /f"
Start-Process shutdown.exe -ArgumentList $shutdown