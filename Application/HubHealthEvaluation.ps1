<#
.SYNOPSIS
    Evaluates the overall health of the Workspace ONE hub and triggers notifications when issues are detected.

.DESCRIPTION
    The HubHealthEvaluation.ps1 script serves as the primary diagnostic tool within the Workspace ONE Autorecovery solution.
    It aggregates health data from multiple checks—including connectivity tests, service status validations, and log verifications—
    to determine the overall state of the Workspace ONE environment. If any issues are identified, the script can trigger alerts
    (such as sending email notifications) and log detailed information to facilitate troubleshooting and recovery operations.

    This script leverages several supporting function modules:
      - General_Functions.ps1
      - OMA-DM_Status_Check_Functions.ps1
      - SQL_Functions.ps1
      - UEM_Status_Check_Functions.ps1

    It is intended to be scheduled (e.g., via Windows Task Scheduler) to run at regular intervals, ensuring continuous
    monitoring of your Workspace ONE hub.

.PARAMETERS
    -ExpectedHash (required)
        Validates the Hash value for this scripts and stops if it was modified
    -providerID (optional)
        For Workspace ONE UEM use "AirtwachMDM" - selected by default
    -logFilePath (optional)
        Provide a log path if you don't want to use the default path

.EXAMPLE
    PS> .\HubHealthEvaluation.ps1 -ExpectedHash "123123"
    Runs the health evaluation process, performs necessary service checks, and outputs the current status of the Workspace ONE environment.
    This script should be scheduled to run periodically to maintain continuous health monitoring.

.NOTES
    Author       : Grischa Ernst
    Date         : 2025-08-29
    Version      : 1.1.0
    Requirements : PowerShell 5.1 or later / PowerShell Core 7+, proper configuration of supporting scripts, and access to Workspace ONE UEM endpoints.
    Purpose      : To monitor the health of the Workspace ONE hub, detect issues, and initiate notification and remediation processes as needed.
    Dependencies : Relies on supporting function files (General_Functions.ps1, OMA-DM_Status_Check_Functions.ps1, SQL_Functions.ps1, UEM_Status_Check_Functions.ps1).
    Execution    : Intended to be executed as part of an automated scheduled task for continuous monitoring.

.CHANGE LOG
    1.1.0   New Features:
                -   Added support for registry based config overwrites
                    This will help to change the settings after the initial installation. New settings can be stored here: 'HKLM:\SOFTWARE\UEMRecovery\ConfigOverride'
                    Naming is the same for normal settings, credentials need an "Overwrite" in front - so e.g. "OverrideUrl" for "URL"
                -   Changed the lockscreen trigger to run automatically if the UEMEnrollment user logs in instead of in the recovery.ps1
                -   Limited the runtime of the enrollment scheduled task to 30 minutes + created a watchdog that breaks the recovery script after 
                    minutes and starts the cleanup
            Bugfixes:
                -   Changed the logic in the enrollment function to also support immediately enrollment outside of the current user session
                -   Added the default domain to the auto logon config
    1.0.0   Initial Release

.LICENSE
    Distributed under the terms specified in the license.md file.
#>



param(
    # Specify the MDM provider ID (e.g., "AirwatchMDM", "IntuneMDM", "CustomMDM")
    [ValidateSet("AirwatchMDM", "IntuneMDM", "CustomMDM")]
    [Parameter(HelpMessage = "Specify the MDM provider ID (e.g., 'AirwatchMDM', 'IntuneMDM', 'CustomMDM')")]
    [string]$providerID = "AirwatchMDM",

    # Path to the log file where script output will be saved
    [Parameter(HelpMessage = "Path to the log file where script output will be saved")]
    [string]$logFilePath = "C:\Windows\UEMRecovery\Logs\MDM_Validation_Log.log",

    #The Hash value for this script, to make sure the script was not modified
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash

)

#Set the install directory
$DestinationPath = "C:\Windows\UEMRecovery"

# Define the path to the SQLLite Data
$SQLPath = "$($DestinationPath)\SQLite"

# Adjust the path to where your System.Data.SQLite.dll is located and unblock files
Get-ChildItem -Path $SQLPath | Unblock-File

# Add the .dll to work with SQLite
Add-Type -Path "$($SQLPath)\System.Data.SQLite.dll"

# Define the SQLite database file path
$dbPath = "$DestinationPath\HUBHealth.sqlite"


#Import Functions
. "$PSScriptRoot\UEM_Status_Check_Functions.ps1"
. "$PSScriptRoot\OMA-DM_Status_Check_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"
. "$PSScriptRoot\SQL_Functions.ps1"

# Start PowerShell Transcript to Capture Console Output
if ($logFilePath) {
    Stop-Transcript -ErrorAction SilentlyContinue
    if (Test-Path $logFilePath) {
        Remove-Item -Path $logFilePath -Force
    }
    
    Start-Transcript -Path $logFilePath -NoClobber -ErrorAction SilentlyContinue
}


###################################################################
#Script Validation

# Path to the current script
$scriptPath = $MyInvocation.MyCommand.Path

try {
    # Calculate the hash of the current script
    $actualHash = Get-FileHash -Path $scriptPath -Algorithm SHA256

    # Compare the actual hash with the expected hash
    if ($actualHash.hash -ne $ExpectedHash) {
        Write-Error "File hash mismatch! The script may have been modified."
        exit 1
    }

    Write-Output "File hash validation passed. Executing the script..."

}
catch {
    Write-Error "An error occurred during hash validation or script execution: $_"
    exit 1
}



####################################################################
# Start Script 

if (Wait-ForSQLiteUnlock -DbPath $dbPath -MaxAttempts 10 -DelaySeconds 1) {
    # Proceed with your database operations.
}
else {
    Write-Error "Cannot proceed because the database remains locked."
}


# Registry Config + Credentials Overrides
Write-Output "Checking for new settings"
$overrideKey = 'HKLM:\SOFTWARE\UEMRecovery\ConfigOverride'
if (Test-Path $overrideKey) {
    Write-Output "New settings detected - writing to SQL Databse" 
    # Read all values under the override key
    $overrideProps = Get-ItemProperty -Path $overrideKey

    # Split out config overrides vs credential overrides
    $configData = @{}
    $credentialOverrides = @{}

    foreach ($prop in $overrideProps.PSObject.Properties) {
        switch ($prop.Name) {
            # Skip the automatic PS* properties
            { $_ -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } { continue }

            # Match credential overrides
            'OverrideUrl' { $credentialOverrides['Url'] = $prop.Value; continue }
            'OverrideUsername' { $credentialOverrides['Username'] = $prop.Value; continue }
            'OverridePassword' { $credentialOverrides['Password'] = $prop.Value; continue }
            'OverrideOG' { $credentialOverrides['OG'] = $prop.Value; continue }

            # Everything else goes into configuration overrides
            default {
                # If value is empty, store literal NULL
                $val = if ([string]::IsNullOrEmpty($prop.Value)) { 'NULL' } else { $prop.Value }
                $configData[$prop.Name] = $val
            }
        }
    }

    # 2a) Apply Config Overrides
    if ($configData.Count) {
        Write-output "Applying configuration overrides from registry..."
        Insert-SQLiteRecord `
            -DbPath $dbPath `
            -TableName 'Configurations' `
            -Data $configData `
            -Overwrite `
            -UniqueCondition '1=1'
    }

    # 2b) Merge & Apply Credential Overrides
    if ($credentialOverrides.Count) {
        # First, read the encryption key from your Configurations (or Encryption) table:
        $encKey = Read-SQLiteTable -DbPath $dbPath -TableName "Encryption" | select EncryptionKey -ExpandProperty EncryptionKey
        if (-not $encKey) {
            Write-Error "EncryptionKey not found in Configurations. Cannot decrypt/overwrite credentials."
            exit 1
        }

        Write-Host "Merging credential overrides from registry with existing database values..."

        # Read existing, encrypted credentials (decrypting with key):
        $currentCred = Read-CredentialsRecord -DbPath $dbPath -EncryptionKey $encKey | Select-Object -First 1
        if (-not $currentCred) {
            Write-Error "No existing credentials found in DB. Cannot merge overrides."
        }
        else {
            # Build merged hashtable, preserving fields not overridden
            $merged = @{
                Url      = if ($credentialOverrides.ContainsKey('Url')) { $credentialOverrides.Url }      else { $currentCred.Url }
                Username = if ($credentialOverrides.ContainsKey('Username')) { $credentialOverrides.Username } else { $currentCred.Username }
                Password = if ($credentialOverrides.ContainsKey('Password')) { $credentialOverrides.Password } else { $currentCred.Password }
                OG       = if ($credentialOverrides.ContainsKey('OG')) { $credentialOverrides.OG }       else { $currentCred.OG }
            }

            # Overwrite the single credential row—Write-CredentialsRecord will re-encrypt using the same key:
            Write-Host "Overwriting credentials in database..."
            Write-CredentialsRecord `
                -DbPath    $dbPath `
                -Url       $merged.Url `
                -Username  $merged.Username `
                -Password  $merged.Password `
                -OG        $merged.OG `
                -EncryptionKey $encKey
        }
    }

    # 3) Clean up the override hive so it only applies once
    Remove-Item -Path $overrideKey -Recurse -Force
    Write-Output "Registry override key removed."
}


#Get the configuration
$Configuration = Read-SQLiteTable -DbPath $dbPath -TableName "Configurations"

#Cleanup the DB 
$CleanupTables = @("OMADM", "HUB", "SFD", "WNS", "Eventlog", "TaskScheduler")
Foreach ($Table in $CleanupTables) {
    Remove-SQLiteOldEntries -DbPath $dbPath -TableName "OMADM" -Days '14'
}


# Check if Device is enrolled (Workspace ONE and OMA-DM)
$EnrollmentStatus = Test-EnrollmentStatus

#Run the different health checks
if ($EnrollmentStatus.PSObject.Properties.Value -notcontains $false) {

    $MDMEnrollmentErrorStatus = Get-MDMEnrollmentDetails -ProviderID "AirwatchMDM" -DbPath $dbPath
    $ScheduledTaskErrorStatus = Test-ScheduledTasks -activeMDMID $MDMEnrollmentErrorStatus[0]  -DbPath $dbPath
    $IntelligentHubErrorStatus = Get-WorkspaceONEHubStatus -DbPath $dbPath
    $EventLogErrorStatus = Get-CategorizedEventLogs -DbPath $dbPath
    $WNSErrorStatus = Get-WNSStatus -DbPath $dbPath -activeMDMID $MDMEnrollmentErrorStatus[0]
    $OMADMErrorStatus = Get-OMADMConnectionInfo -DbPath $dbPath -activeMDMID $MDMEnrollmentErrorStatus[0]
    $AWCMErrorStatus = Test-AWCMCommunication -DbPath $dbPath 
    $SFDErrorStatus = Test-SFDTasks -DbPath $dbPath
    $ProxyErrorStatus = Test-ProxyConfig -DbPath $dbPath
    $RebootStatus = Test-PendingReboot -DbPath $dbPath
    $SFDTest = Test-SFDTasks -DbPath $dbPath


    # CHeck if the Error Threshold is reached
    $ErrorThresholdReached = Test-ErrorsThreshold -DbPath $dbPath -IndividualThreshold ($Configuration.IndividualThreshold) -OverallThreshold ($Configuration.OverallThreshold)

    # Generate HTML report and save it in the HUB Logs folder
    New-HTMLReport -DbPath $dbPath -OutputFile "C:\ProgramData\AirWatch\UnifiedAgent\Logs\DeviceHealthStatus.html"

    if ($ErrorThresholdReached -eq $True) {
        if (($Configuration.AutoReEnrollment) -eq "True") {
            if (($Configuration.EnrollmentDefinedDate) -eq "True") {
                
                # Create scheduled task to re-enroll the device

                # Variables
                $taskName = "WorkspaceONE Autorepair"
                $timeOfDay = "$($Configuration.EnrollmentTime)"
                $dayOfWeek = "$($Configuration.EnrollmentDay)"

                # Check for Existing Scheduled Task
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }

                if (($Configuration.ReEnrollmentWithCurrentUserSession) -eq "True") {
                    $scriptPath = "$($DestinationPath)\recovery.ps1"

                    # Set the task to run as loggendin User
                    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -LogonType Interactive
                }
                elseif (($Configuration.ReEnrollmentWithCurrentUserSession) -eq "False") {
                    $scriptPath = "$($DestinationPath)\UEM_automatic_reenrollment.ps1"

                    # Set the task to run as SYSTEM
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
                }
                    
                # Create an action to run the PowerShell script
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $expectedHash"

                # Create a trigger to run the task weekly on the specified day and time
                $trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek


                # Register the task
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

                Write-Output "Scheduled task '$taskName' created successfully to run every $dayOfWeek at $timeOfDay."

                
            }
            else {
                # Execute the reenrollment process
                $RecoveryScript = "-NoProfile -ExecutionPolicy Bypass -File `"$($PSScriptRoot)\recovery.ps1`""
        
                try {
                    Write-Log "Starting execution of recovery.ps1." "INFO"
                   
                    # Start the process and capture the process object.
                    $proc = Start-Process powershell.exe -ArgumentList $RecoveryScript -Wait -PassThru -ErrorAction Stop
                   
                    # Check the exit code.
                    if ($proc.ExitCode -eq 0) {
                        Write-Log "recovery.ps1 executed successfully. Exit code: $($proc.ExitCode)" "INFO"
                    }
                    else {
                        Write-Log "recovery.ps1 failed with exit code: $($proc.ExitCode)" "ERROR"
                        exit $proc.ExitCode
                    }
                }
                catch {
                    Write-Log "Error executing recovery.ps1: $_" "ERROR"
                    exit 1
                }
            }
        }
    }
}
else {
    if (($Configuration.EnrollIfNotEnrolled) -eq "True") {
        if (($Configuration.EnrollmentDefinedDate) -eq "True") {
    
            $taskName = "WorkspaceONE Recovery"
            $timeOfDay = "$($Configuration.EnrollmentTime)"

            # Normalize EnrollmentDay to array
            $daysRaw = $Configuration.EnrollmentDay
            if ($daysRaw -is [string]) {
                $dayOfWeek = $daysRaw -split '[,\s]+' | Where-Object { $_ -ne "" }
            }
            elseif ($daysRaw -is [array]) {
                $dayOfWeek = $daysRaw
            }
            else {
                Throw "Invalid format for EnrollmentDay: $daysRaw"
            }

            # Remove existing scheduled task if it exists
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }

            # Set script path and principal
            if (($Configuration.EnrollDuringCurrentUserSession) -eq "True") {
                $scriptPath = "$DestinationPath\recovery.ps1"
                $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -LogonType Interactive
            }
            else {
                $scriptPath = "$DestinationPath\UEM_automatic_reenrollment.ps1"
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            }

            # Define the task action
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

            # Define the weekly trigger
            $trigger = New-ScheduledTaskTrigger -Weekly -At $timeOfDay -DaysOfWeek $dayOfWeek

            # Define task settings: 30 minute execution time limit
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

            # Register the task
            Register-ScheduledTask -TaskName $taskName `
                -Action $action `
                -Trigger $trigger `
                -Principal $principal `
                -Settings $settings

            Write-Output "Scheduled task '$taskName' created to run at $timeOfDay on: $($dayOfWeek -join ', ') with 30 min execution limit."
        }

        else {
            if (($Configuration.EnrollDuringCurrentUserSession) -eq "True") {
                # Immediate execution of recovery.ps1 as current user
                $RecoveryScript = "-NoProfile -ExecutionPolicy Bypass -File `"$($PSScriptRoot)\recovery.ps1`""

                try {
                    Write-Log "Starting execution of recovery.ps1." "INFO"
                    $proc = Start-Process powershell.exe -ArgumentList $RecoveryScript -Wait -PassThru -ErrorAction Stop

                    if ($proc.ExitCode -eq 0) {
                        Write-Log "recovery.ps1 executed successfully. Exit code: $($proc.ExitCode)" "INFO"
                    }
                    else {
                        Write-Log "recovery.ps1 failed with exit code: $($proc.ExitCode)" "ERROR"
                        exit $proc.ExitCode
                    }
                }
                catch {
                    Write-Log "Error executing recovery.ps1: $_" "ERROR"
                    exit 1
                }
            }
            else {
                # Schedule SYSTEM task to run in 5 minutes, then log off current user
                $taskName = "WorkspaceONE Recovery"
                $scriptPath = "$DestinationPath\UEM_automatic_reenrollment.ps1"
                $triggerTime = (Get-Date).AddMinutes(5)
                $startTime = $triggerTime.ToString("HH:mm")

                # Clean up existing task if present
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }

                # Build principal, action, trigger, and settings
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
                $trigger = New-ScheduledTaskTrigger -Once -At $triggerTime
                $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

                # Register the scheduled task
                Register-ScheduledTask -TaskName $taskName `
                    -Action $action `
                    -Trigger $trigger `
                    -Principal $principal `
                    -Settings $settings

                Write-Log "Scheduled SYSTEM task '$taskName' to run at $startTime." "INFO"

                # Log off current user
                try {
                    Write-Log "Logging off current user..." "INFO"
                    shutdown.exe /l
                }
                catch {
                    Write-Log "Failed to log off current user: $_" "ERROR"
                }
            }
        }

    }
}

