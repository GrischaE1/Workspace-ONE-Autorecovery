<#
.SYNOPSIS
    Orchestrates recovery actions for non-compliant devices in the Workspace ONE UEM environment.

.DESCRIPTION
    The recovery.ps1 script serves as the central orchestrator for initiating recovery actions when issues are detected in the Workspace ONE environment.
    It integrates detection results from health checks with the re-enrollment logic to restore devices to a compliant state.
    By coordinating the remediation process—potentially invoking additional scripts or functions such as UEM_automatic_reenrollment.ps1—this script
    ensures that devices which have fallen out of compliance are automatically re-enrolled and returned to proper management.
    This script is designed to be triggered automatically as part of an overall remediation workflow following health evaluation procedures.

.PARAMETERS
    None

.EXAMPLE
    PS> .\recovery.ps1
    Executes the recovery process to re-enroll devices and perform necessary remediation actions based on detected issues.
    It is recommended to schedule this script to run automatically after the health evaluation script has identified problems.

.NOTES
    Author       : Grischa Ernst
    Date         : 2025-10-20
    Version      : 1.0.2
    Requirements : PowerShell 5.1 or later / PowerShell Core 7+, access to Workspace ONE UEM endpoints, and properly configured supporting modules.
    Purpose      : To orchestrate and execute the recovery process by integrating health check outputs with re-enrollment actions.
    Dependencies : May invoke or work in tandem with UEM_automatic_reenrollment.ps1 and relies on supporting functions provided in the solution.
    Execution    : Intended to be executed as part of an automated remediation workflow, either scheduled or triggered by health evaluation results.

.LICENSE
    Distributed under the terms specified in the license.md file.
#>


param(
    # Path to the log file where script output will be saved
    [Parameter(HelpMessage = "Path to the log file where script output will be saved")]
    [string]$logFilePath = "C:\Windows\UEMRecovery\Logs\recovery.log"
)


# Generate timestamp for log filename (format: yyyy-MM-dd_HH-mm-ss)
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# If the log file path wasn't explicitly provided, use default with timestamp
if (-not $PSBoundParameters.ContainsKey('logFilePath')) {
    $logFilePath = "C:\Windows\UEMRecovery\Logs\recovery_$timestamp.log"
}

# --- helpers

function Clear-SQLiteErrorCounter {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DbPath,

        [int]$MaxRetries = 5,
        [int]$DelaySeconds = 3
    )

    $retryCount = 0
    $success = $false

    # Validate DB path
    if (-not (Test-Path $DbPath)) {
        Write-Log "ERROR: Database not found at path: $DbPath" -Severity "ERROR"
        return
    }

    while (-not $success -and $retryCount -lt $MaxRetries) {
        try {
            # Load SQLite if not already loaded
            if (-not ([System.Data.SQLite.SQLiteConnection]::Assembly)) {
                Add-Type -Path "$PSScriptRoot\SQLite\System.Data.SQLite.dll"
                Write-Log "Loaded SQLite assembly from $PSScriptRoot\SQLite\System.Data.SQLite.dll"
            }

            $connectionString = "Data Source=$DbPath;Version=3;"
            $connection = New-Object System.Data.SQLite.SQLiteConnection $connectionString
            $connection.Open()
            Write-Log "Opened SQLite connection to $DbPath"

            $sql = "DELETE FROM Errors;"
            $command = $connection.CreateCommand()
            $command.CommandText = $sql
            $rowsAffected = $command.ExecuteNonQuery()

            $connection.Close()

            Write-Log "All error entries cleared successfully. Rows affected: $rowsAffected" -Severity "INFO"
            $success = $true
        }
        catch {
            $retryCount++
            Write-Log "Attempt $retryCount : Failed to reset error entries: $_" -Severity "WARNING"

            if ($retryCount -lt $MaxRetries) {
                Write-Log "Retrying in $DelaySeconds seconds..."
                Start-Sleep -Seconds $DelaySeconds
            }
            else {
                Write-Log "All retries failed. Could not reset error entries." -Severity "ERROR"
                throw $_
            }
        }
    }
}



# --- Global timeout watchdog (28 minutes)
$GlobalTimeoutMinutes = 28


#importing the SQL functions
. "$PSScriptRoot\SQL_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"

# Define the path to the SQLLite Data
$SQLPath = "$($PSScriptRoot)\SQLite"

# Add the .dll to work with SQLite
Add-Type -Path "$($SQLPath)\System.Data.SQLite.dll"

# Define the SQLite database file path
$dbPath = "$PSScriptRoot\HUBHealth.sqlite"

# Start PowerShell Transcript to Capture Console Output
if ($logFilePath) {
    Stop-Transcript -ErrorAction SilentlyContinue
    if (Test-Path $logFilePath) {
        Remove-Item -Path $logFilePath -Force
    }
    
    Start-Transcript -Path $logFilePath -NoClobber -ErrorAction SilentlyContinue
}


$enrollmentStatus = Test-EnrollmentStatus

$Configuration = Read-SQLiteTable -DbPath $dbPath -TableName "Configurations"
if (-not $Configuration -or $Configuration.Count -eq 0) {
    Write-Error "Failed to read configuration from the database. Aborting script."
    exit 1
}

$EncryptionKey = Read-SQLiteTable -DbPath $dbPath -TableName "Encryption" | select EncryptionKey -ExpandProperty EncryptionKey

$UEMCredentials = Read-CredentialsRecord -DbPath $dbPath -EncryptionKey $EncryptionKey
if (-not $UEMCredentials -or $UEMCredentials.Count -eq 0) {
    Write-Error "Failed to read credentials from the database. Aborting script."
    exit 1
}


$WSOStagingUser = "$($UEMCredentials.Username)"
$WSOStagingPW = "$($UEMCredentials.Password)"
$WSOOGID = "$($UEMCredentials.OG)"
$WSOServer = "$($UEMCredentials.Url)"

Write-Log "Starting recovery execution" -Severity "INFO"


#Wait for explorer to be started
do {
    Write-Log "Waiting for explorer to get started" -Severity "INFO"
    $Process = Get-Process -Name explorer
    Start-Sleep 20 
    if ($Process) {            
        Write-Log "Explorer started, starting Screenlock Scheduled Task" -Severity "INFO"
        if ($Configuration.ReEnrollmentWithCurrentUserSession -eq $false -or $Configuration.EnrollDuringCurrentUserSession -eq $false) {
            #lock device screen
            Start-ScheduledTask "Screenlock"
        }
    }
        
}while (!$Process)

# Download Workspace ONE Agent
try {
    Write-Log "Workspace ONE Agent download started" -Severity "INFO"
    $WebClient = New-Object System.Net.WebClient
    $agentPath = "C:\Windows\UEMRecovery\AirwatchAgent.msi"
    $WebClient.DownloadFile("https://$($WSOServer)/agents/ProtectionAgent_autoseed/airwatchagent.msi", $agentPath)
    Write-Log "Workspace ONE Agent downloaded successfully to $agentPath." -Severity "INFO"
}
catch {
    Write-Log "Failed to download Workspace ONE Agent: $_" -Severity "ERROR"
    exit 1
}


Start-Job -Name "RecoveryWatchdog" -ArgumentList $GlobalTimeoutMinutes -ScriptBlock {
    param($timeoutMinutes)
    Start-Sleep -Seconds ($timeoutMinutes * 60)

    # Cleanup autologon registry keys
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $RegistryPath) {
        Remove-ItemProperty $RegistryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
        Remove-ItemProperty $RegistryPath -Name "DefaultUsername" -ErrorAction SilentlyContinue
        Remove-ItemProperty $RegistryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
        Remove-ItemProperty $RegistryPath -Name "DefaultDomain" -ErrorAction SilentlyContinue
    }

    $logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    if (Test-Path $logonPath) {
        Set-ItemProperty $logonPath -Name "LastLoggedOnUser" -Value "" -ErrorAction SilentlyContinue
        Set-ItemProperty $logonPath -Name "LastLoggedOnUserSID" -Value "" -ErrorAction SilentlyContinue
        Set-ItemProperty $logonPath -Name "LastLoggedOnDisplayName" -Value "" -ErrorAction SilentlyContinue
        Set-ItemProperty $logonPath -Name "LastLoggedOnSamUser" -Value "" -ErrorAction SilentlyContinue
        Set-ItemProperty $logonPath -Name "SelectedUserSID" -Value "" -ErrorAction SilentlyContinue
    }

    Unregister-ScheduledTask -TaskName "WorkspaceONE Enrollment" -Confirm:$false

    Add-Content -Path "C:\Windows\UEMRecovery\Logs\recovery.log" -Value \"[Watchdog] Timeout reached. Cleanup executed. Exiting script.\"
    
    Stop-Process -Id $PID -Force  # kill the main script process

} | Out-Null



# Get Enrollment ID
if ($enrollmentStatus.IsWorkspaceONEEnrolled -eq $True -or $enrollmentStatus.IsOMADMEnrolled -eq $true) {
    Write-Log "Attempting to retrieve Enrollment ID."
    try {
        # Retrieve all items under the Enrollment registry key
        $AllItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse -ErrorAction Stop
        $AirWatchMDMKey = $AllItems | Where-Object { $_.Name -like "*AirWatchMDM" }

        # Ensure the AirWatchMDMKey exists
        if (-not $AirWatchMDMKey) {
            throw "No AirWatchMDM key found in the registry."
        }

        # Extract the Enrollment Key using regex
        $pattern = "Enrollments\\(.*?)\\DMClient"
        $EnrollmentKey = ([regex]::Match(($AirWatchMDMKey.PSPath), $pattern).Groups[1].Value).Replace("\\", "")

        if (-not $EnrollmentKey) {
            throw "Failed to extract Enrollment Key using the specified regex pattern."
        }

        Write-Log "Enrollment key retrieved successfully: $EnrollmentKey."
    }
    catch {
        Write-Log "Failed to retrieve Enrollment ID: $_" -Severity "ERROR"
        exit 1
    }
}
    
# Uninstall SFD to avoid application uninstallation
Write-Log "Attempting to uninstall SFD Agent."
try {
    # Retrieve the SFD Agent registry entry
    $Registry = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction Stop | Where-Object { $_.GetValue('DisplayName') -like "*SfdAgent*" }

    # Ensure the registry entry exists
    if (-not $Registry) {
        throw "SFD Agent registry entry not found."
    }

    # Construct the uninstall command
    $SFDUninstall = "/x $($Registry.PSChildName) /q"

    # Execute the uninstall process
    Start-Process MsiExec.exe -ArgumentList $SFDUninstall -Wait -ErrorAction Stop
    Write-Log "SFD Agent uninstalled successfully."
}
catch {
    Write-Log "Failed to uninstall SFD Agent: $_" -Severity "ERROR"
}


# Remove SFD and OMA-DM Registry keys
Write-Log "Attempting to remove SFD and OMA-DM registry keys."
try {
    # Remove Registry Keys
    $registryKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\EnterpriseDesktopAppManagement",
        "HKLM:\\SOFTWARE\\AirWatchMDM"
    )

    foreach ($key in $registryKeys) {
        try {
            if (Test-Path $key) {
                Remove-Item $key -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully removed registry key: $key."
            }
            else {
                Write-Log "Registry key not found: $key." -Severity "WARNING"
            }
        }
        catch {
            Write-Log "Failed to remove registry key: $key. Error: $_" -Severity "ERROR"
        }
    }
}
catch {
    Write-Log "Error occurred while attempting to remove SFD and OMA-DM registry keys: $_" -Severity "ERROR"
}

# Uninstall Intelligent Hub
Write-Log "Attempting to uninstall Intelligent Hub."
if ($enrollmentStatus.WorkspaceONEInstalled -eq $True) {
    try {
        # Retrieve Intelligent Hub installation data
        $HubData = Get-WmiObject Win32_Product -ErrorAction Stop | Where-Object { $_.Name -like "*Intelligent HUB Installer*" }

        # Validate if Intelligent Hub is found
        if ($HubData) {
            # Construct the uninstall command
            $HubUninstall = "/x $($HubData.IdentifyingNumber) /q"

            # Execute the uninstall process
            Start-Process MsiExec.exe -ArgumentList $HubUninstall -Wait -ErrorAction Stop
            Write-Log "Intelligent Hub uninstalled successfully."
        }
        else {
            Write-Log "Intelligent Hub is not installed or could not be found." -Severity "WARNING"
        }
    }
    catch {
        Write-Log "Failed to uninstall Intelligent Hub: $_" -Severity "ERROR"
    }


    #Sleep for 60 seconds to make sure Hub is uninstalled
    Start-Sleep -Seconds 60

    # Uninstall WS1 App
    Write-Log "Attempting to uninstall WS1 app."
    try {
        # Retrieve the WS1 app package
        $WS1App = Get-AppxPackage *AirWatchLLC* -ErrorAction SilentlyContinue

        # Validate if the app package exists
        if ($WS1App) {
            # Attempt to remove the app package
            $WS1App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Log "WS1 app uninstalled successfully."
        }
        else {
            Write-Log "WS1 app is not installed or could not be found." -Severity "WARNING"
        }
    }
    catch {
        Write-Log "Failed to uninstall WS1 app: $_" -Severity "ERROR"
    
    }
}

# Remove Enrollment Registry Keys
Write-Log "Attempting to remove Enrollment registry keys."
$registryKeys = @(
    "HKLM:\SOFTWARE\AirWatch",
    "HKLM:\SOFTWARE\Microsoft\Enrollments",
    "HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\logger",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID",
    "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($EnrollmentKey)",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxDefault\$($EnrollmentKey)",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($EnrollmentKey)",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\_ContainerAdmxDefault\*",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\device\ApplicationManagement\*",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($EnrollmentKey)",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Session\$($EnrollmentKey)",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsAnytimeUpgrade\Attempts\*"
    "HKLM:\SOFTWARE\WorkspaceONE"
    "HKLM:\SOFTWARE\AirWatchMDMBackup"
    "HKLM:\SOFTWARE\VMware, Inc.\VMware EUC"
    "HKLM:\SOFTWARE\VMware, Inc.\VMware Endpoint Telemetry"

)

foreach ($key in $registryKeys) {
    try {
        if (Test-Path $key) {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Successfully removed registry key: $key."
        }
        else {
            Write-Log "Registry key not found: $key." -Severity "WARNING"
        }
    }
    catch {
        Write-Log "Failed to remove registry key: $key. Error: $_" -Severity "ERROR"
    }
}

Write-Log "Delete files and information that may have been left behind"


#Delete folders
$directorypaths = @(
    "$env:ProgramData\AirWatch",
    "$env:ProgramData\VMware\SfdAgent",
    "$env:ProgramFiles\WorkspaceONE",
    "$env:ProgramData\VMware\vmwetlm",
    "$env:ProgramData\VMware\EUC",
    "$env:ProgramData\WorkspaceONE"
)

foreach ($directory in $directorypaths) {
    try {
        if (Test-Path $directory) {
            Remove-Item $directory -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Successfully removed directory: $directory."
        }
        else {
            Write-Log "Directory  not found: $directory." -Severity "WARNING"
        }
    }
    catch {
        Write-Log "Failed to remove directory: $directory. Error: $_" -Severity "ERROR"
    }
}

#Clean Scheduled Tasks - SFD
Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($EnrollmentKey)\*" | Unregister-ScheduledTask  -Confirm:$false

$scheduleObject = New-Object -ComObject Schedule.Service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
$rootFolder.DeleteFolder("$($EnrollmentKey)", $null)

#Clean Scheduled Tasks - SFD - before 24.10
Get-ScheduledTask -TaskPath "\vmware\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

$scheduleObject = New-Object -ComObject Schedule.Service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\vmware")
$rootFolder.DeleteFolder("SfdAgent", $null)

#Clean Scheduled Tasks - SFD - after 24.10
Get-ScheduledTask -TaskPath "\Workspace ONE\SfdAgent\*" | Unregister-ScheduledTask  -Confirm:$false

$scheduleObject = New-Object -ComObject Schedule.Service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\Workspace ONE")
$rootFolder.DeleteFolder("SfdAgent", $null)
    

#Delete user certificates
$UserCerts = Get-ChildItem cert:"CurrentUser" -Recurse
$UserCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

#Delete device certificates
$DeviceCerts = Get-ChildItem cert:"LocalMachine" -Recurse
$DeviceCerts | Where-Object { $_.Issuer -like "*AirWatch*" -or $_.Issuer -like "*AwDeviceRoot*" } | Remove-Item -Force

# Enroll the device to UEM
Write-Log "Starting enrollment process for the device."
try {
    # Construct the argument list for enrollment
    $List = "/q ENROLL=Y SERVER=https://$($WSOServer) LGName=$($WSOOGID) USERNAME=$($WSOStagingUser) PASSWORD=$($WSOStagingPW) ASSIGNTOLOGGEDINUSER=Y"
    
    # Execute the enrollment process
    Start-Process "C:\Windows\UEMRecovery\AirwatchAgent.msi" -ArgumentList $List -Wait -ErrorAction Stop
    Write-Log "Device enrollment initiated successfully."
}
catch {
    Write-Log "Failed to install Intelligent Hub: $_" -Severity "ERROR"
    $global:scriptError = $true
    exit 1
}



#Generate 10 minute timer
$timeout = new-timespan -Minutes 10
$sw = [diagnostics.stopwatch]::StartNew()
$enrollcheck = $false
$i = 0
do {
    $i++
    Start-Sleep -Seconds 10
    Write-Log "Start enrollment check No. $($i)"

    #Check every 10 seconds if the device is enrolled
    $enrolltemp = Get-Item -Path "HKLM:\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction SilentlyContinue
    if ($enrolltemp) {
        If ($enrolltemp.GetValue("Status") -eq 'Completed') {
            $enrollcheck = $true
        
            Write-Log "Device enrolled successfully."

            # Disable the Scheduled Task
            Write-Log "Attempting to delete the scheduled task 'WorkspaceONE Recovery'."
            try {
                Unregister-ScheduledTask -TaskName "WorkspaceONE Recovery" -Confirm:$false
                Unregister-ScheduledTask -TaskName "WorkspaceONE Enrollment" -Confirm:$false
                Write-Log "Scheduled task 'WorkspaceONE Recovery' successfully deleted."
            }
            catch {
                Write-Log "Failed to delete the scheduled task 'WorkspaceONE Recovery': $_" -Severity "ERROR"
               
            }

            Write-Log "Resetting all error counters after successful re-enrollment." -Severity "INFO"

            Clear-SQLiteErrorCounter -DbPath $dbPath
        }
    }
}while ($enrollcheck -eq $false -and $sw.elapsed -lt $timeout)

# Save space and remove the downloaded Hub again
Remove-Item -Path $agentPath -Force

# Kill watchdog if still running
Get-Job -Name "RecoveryWatchdog" -State Running | Stop-Job | Remove-Job


$CurrentUser = $env:USERNAME

if ($CurrentUser -eq "UEMEnrollment") {
    
    Write-Log "Removing registry keys for re-enrollment outside of the user session" -Severity "INFO"
    
    # Remove autologon settings
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Remove-ItemProperty $RegistryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    Remove-ItemProperty $RegistryPath -Name "DefaultUsername" -ErrorAction SilentlyContinue
    Remove-ItemProperty $RegistryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue
    Remove-ItemProperty $RegistryPath -Name "DefaultDomain" -ErrorAction SilentlyContinue

    # Remove login screen traces
    $logonPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    New-ItemProperty $logonPath -Name "LastLoggedOnUser" -PropertyType String -Value "" -Force
    New-ItemProperty $logonPath -Name "LastLoggedOnUserSID" -PropertyType String -Value "" -Force
    New-ItemProperty $logonPath -Name "LastLoggedOnDisplayName" -PropertyType String -Value "" -Force
    New-ItemProperty $logonPath -Name "LastLoggedOnSamUser" -PropertyType String -Value "" -Force
    New-ItemProperty $logonPath -Name "SelectedUserSID" -PropertyType String -Value "" -Force

    # Restart the device if cleanup ran outside user session
    $shutdown = "/r /t 20 /f"
    Start-Process shutdown.exe -ArgumentList $shutdown

}

Write-Log "Script Finished - Exit" -Severity "INFO"
exit 0
