<#
.SYNOPSIS
    Installs and configures the Workspace ONE Autorecovery environment.

.DESCRIPTION
    The install.ps1 script sets up the Workspace ONE Autorecovery solution by installing the required components
    into a designated destination path and verifying the integrity of the HubHealthEvaluation.ps1 file via its hash.
    Additionally, the script configures necessary credentials for accessing Workspace ONE UEM resources.
    This script is intended to be run in an elevated PowerShell session on a system where Workspace ONE UEM is deployed.

.PARAMETERS
    -DestinationPath <String>
        Specifies the installation directory where the Workspace ONE Autorecovery components will be installed.
        Default value is "C:\Windows\UEMRecovery".

    -ExpectedHash <String>
        Specifies the expected hash value of the HubHealthEvaluation.ps1 file. This parameter is mandatory
        and is used to verify the integrity of the file before installation proceeds.


.EXAMPLES
    PS C:\Workspace-ONE-Autorecovery> .\install.ps1 `
        -ExpectedHash "ABC123DEF456..." `

    Runs the installation process using the provided parameters, installing files into the default destination
    ("C:\Windows\UEMRecovery") and verifying the HubHealthEvaluation.ps1 file integrity with the expected hash.

.NOTES
    Author        : Grischa Ernst
    Date          : 2025-02-15
    Version       : 1.0.0
    Requirements  : 
                      - PowerShell 5.1 or later / PowerShell Core 7+
                      - Administrator privileges
                      - Access to Workspace ONE UEM endpoints
    Purpose       : To prepare and configure the Workspace ONE Autorecovery environment, ensuring that the installation 
                    directory is set, the HubHealthEvaluation.ps1 file is verified, and proper credentials are configured.
    Dependencies  : A valid configuration (credentials and expected hash) must be provided.
    
.LICENSE
    Distributed under the terms specified in the license.md file.
#>


param (
    [Parameter(Mandatory = $false)]
    [string]$DestinationPath = "C:\Windows\UEMRecovery",

    #Expected Hash of the HubHealthEvaluation.ps1 file
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHash
)

Start-Transcript -Path C:\Temp\install.log -Force

# Load SQL Functions
. "$PSScriptRoot\SQL_Functions.ps1"
. "$PSScriptRoot\General_Functions.ps1"

# load config 
# Get the config data
$configData = Get-Content -Path "$PSScriptRoot\config.json" -Raw | ConvertFrom-Json
$UEMConfig = $configData.UEMConfig

#Save the config to variable
$CredentialUsername = $UEMConfig.UEMEnrollmentUser
$CredentialPassword = $UEMConfig.UEMEnrollmentPassword
$CredentialOG = $UEMConfig.UEMEnrollmentOG
$CredentialURL = $UEMConfig.UEMEnrollmentURL


# -------------------------------
# Copy Files
# -------------------------------

try {
    # Get the folder where the script is located
    $sourceFolder = Split-Path -Path $MyInvocation.MyCommand.Path

    # Ensure the destination folder is defined
    if (-not $DestinationPath) {
        throw "DestinationPath is not set. Please specify a valid destination folder."
    }

    # Ensure the destination folder exists
    if (-not (Test-Path -Path $DestinationPath)) {
        Write-Output "Destination folder does not exist. Creating it..."
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    function Copy-ItemWithExclusions {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Source,
            [Parameter(Mandatory = $true)]
            [string]$Destination,
            [string[]]$Exclude = @()
        )

        # Create destination if it doesn't exist
        if (-not (Test-Path -Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }

        # Retrieve all items (files and directories) recursively from the source
        $items = Get-ChildItem -Path $Source -Recurse -Force

        foreach ($item in $items) {
            # Determine the relative path to preserve the folder structure
            $relativePath = $item.FullName.Substring($Source.Length).TrimStart('\')
            $destPath = Join-Path -Path $Destination -ChildPath $relativePath

            if ($item.PSIsContainer) {
                # Create the subfolder if it doesn't exist
                if (-not (Test-Path -Path $destPath)) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                }
            }
            else {
                # If the file's name is in the exclusion list, skip it
                if ($Exclude -contains $item.Name) {
                    Write-Output "Excluding file: $($item.Name)"
                    continue
                }
                # Copy the file to the destination, preserving its relative path
                Copy-Item -Path $item.FullName -Destination $destPath -Force
            }
        }
    }

    Write-Output "Copying files and subfolders from '$sourceFolder' to '$DestinationPath' (excluding detection.ps1 and install.ps1)..."
    Copy-ItemWithExclusions -Source $sourceFolder -Destination $DestinationPath -Exclude "detection.ps1", "install.ps1", "dummy.exe", "uninstall.ps1", "WorkspaceONEAUtorecovery.zip"

    Write-Output "Files and subfolders copied successfully to '$DestinationPath'."
}
catch {
    Write-Error "An error occurred: $_"
}

# -------------------------------
# Create Scheduled Task
# -------------------------------

# Variables
$taskName = "WorkspaceONE Autorepair"
$scriptPath = "$($DestinationPath)\HubHealthEvaluation.ps1"

# Check for Existing Scheduled Task
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Warning "Scheduled task '$taskName' already exists. It will be updated."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

try {
    # Create Trigger 1: A daily trigger that repeats every 4 hours.
    $dailyTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -hours 4) 

    # Create Trigger 2: A logon trigger that starts 10 minutes after user logon.
    $logonTrigger = New-ScheduledTaskTrigger -AtLogon -RandomDelay (New-TimeSpan -Minutes 15)

    # Create the action to run the specified PowerShell script.
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ExpectedHash $ExpectedHash"

    # Create task settings: run only if a user is logged on and start when available.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable

    # Create the principal. Running as SYSTEM is common when a task must run in system context.
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    # Register the task with both triggers.
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($dailyTrigger, $logonTrigger) `
        -Settings $settings -Principal $principal

    Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Green

}
catch {
    Write-Host "Scheduled task '$taskName' created successfully." -ForegroundColor Red
    Write-Error "An error occurred: $_"
    exit 1
}


# -------------------------------
# Create SQLite Database and Insert Credentials
# -------------------------------

# Define the path to the SQLLite Data
$SQLPath = "$($DestinationPath)\SQLite"

# Adjust the path to where your System.Data.SQLite.dll is located and unblock files
Get-ChildItem -Path $SQLPath | Unblock-File

# Add the .dll to work with SQLite
Add-Type -Path "$($SQLPath)\System.Data.SQLite.dll"

# Define the SQLite database file path  
$dbPath = "$DestinationPath\HUBHealth.sqlite"

# Create or open the database
New-SQLiteDB -DbPath $dbPath

# Create the SQLite tables if it doesn't exist. 
# Before the Table gets created, the data gets deleted

# Define an array of table definitions as custom objects.
$tables = @(
    @{
        Name             = "Credentials"
        ColumnDefinition = "Name TEXT NOT NULL PRIMARY KEY, EncryptedUrl TEXT NOT NULL, EncryptedPassword TEXT NOT NULL, EncryptedUsername TEXT NOT NULL, encryptedOG TEXT NOT NULL"
    },
    @{
        Name             = "OMADM"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "HUB"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "SFD"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "WNS"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "AWCM"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "Eventlog"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "TaskScheduler"
        ColumnDefinition = "Test TEXT NOT NULL, Result TEXT NOT NULL, Timestamp DATETIME NOT NULL"
    },
    @{
        Name             = "Errors"
        ColumnDefinition = "OMADM_Errorcount INTEGER NOT NULL, HUB_Errorcount INTEGER NOT NULL, WNS_Errorcount INTEGER NOT NULL, ScheduledTask_Errorcount INTEGER NOT NULL, SFD_Errorcount INTEGER NOT NULL, AWCM_Errorcount INTEGER NOT NULL, LastUpdate DATETIME NOT NULL, Overall_Errorcount INTEGER NOT NULL"
    },
    @{
        Name             = "Configurations"
        ColumnDefinition = "OverallThreshold INTEGER, IndividualThreshold INTEGER, ResetAfter INTEGER, ThresholdReached TEXT, ThresholdTimestamp DATETIME DEFAULT NULL, AutoReEnrollment TEXT, EnrollmentDefinedDate TEXT, ReEnrollmentWithCurrentUserSession TEXT, EnrollmentDay TEXT, EnrollmentTime TEXT, EnrollDuringCurrentUserSession TEXT,EnrollIfNotEnrolled TEXT"
    },
    @{
        Name             = "General"
        ColumnDefinition = 'Name TEXT NOT NULL PRIMARY KEY, Value TEXT, "Group" TEXT'
    },
    @{
        Name             = "Encryption"
        ColumnDefinition = 'Name TEXT NOT NULL PRIMARY KEY, EncryptionKey TEXT NOT NULL'
    }
)

if (Wait-ForSQLiteUnlock -DbPath $dbPath -MaxAttempts 10 -DelaySeconds 1) {
    # Proceed with your database operations.
}
else {
    Write-Error "Cannot proceed because the database remains locked."
}

# Loop through each table definition.
foreach ($table in $tables) {
    Remove-SQLiteTable -DbPath $dbPath -TableName $table.Name
    New-SQLiteTable -DbPath $dbPath -TableName $table.Name -ColumnDefinition $table.ColumnDefinition
}

# Save the configuration from the Config File to the DB
Save-Configuration -DbPath $dbPath -ConfigJsonPath "$($DestinationPath)\config.json"


# Generate a new random string for encryption
$EncryptionKey = New-RandomKeyString

$connectionString = "Data Source=$DbPath;Version=3;"
$conn = $null

try {
    # Open the connection.
    $conn = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
    $conn.Open()

    # Use INSERT OR REPLACE to ensure a single row with the key "CurrentCredential" is maintained.
    $sql = "INSERT OR REPLACE INTO Encryption (Name, EncryptionKey)
                VALUES ('UniqueKey', @EncryptionKey);"
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = $sql

    # Bind parameters.
    $paramkey = $cmd.CreateParameter(); $paramkey.ParameterName = "@EncryptionKey"; $paramkey.Value = $EncryptionKey; $cmd.Parameters.Add($paramkey) | Out-Null
        
    $rowsAffected = $cmd.ExecuteNonQuery()
    Write-Host "Credentials updated successfully. Rows affected: $rowsAffected" -ForegroundColor Green
}
catch {
    Write-Error "Error in Updating the Encrpytion Key $_"
}
finally {
    if ($conn -and $conn.State -eq 'Open') {
        $conn.Close()
    }
}



# Insert the credentials record into the Credentials table.
Write-CredentialsRecord -DbPath $dbPath -URL $CredentialURL -Password $CredentialPassword -Username $CredentialUsername -OG $CredentialOG -EncryptionKey $EncryptionKey

Write-Output "Installation complete."

# Lock down the DB - only access for administators or system account
Set-FileExclusiveAcl -FilePath $dbPath

Stop-Transcript