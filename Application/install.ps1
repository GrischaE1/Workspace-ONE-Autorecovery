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
    Author       : Grischa Ernst
    Date         : 2025-12-15
    Version      : 1.1.1
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
$taskName = "WorkspaceONE Hub Health"
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

# -------------------------------
# Prepare SQLite Environment (x64 only) with VC++ Redistributable Check
# -------------------------------

function Test-SQLiteLoaded {
    <#
    .SYNOPSIS
    Tests if SQLite can be loaded and accessed.
    #>
    try {
        $version = [System.Data.SQLite.SQLiteConnection]::SQLiteVersion
        Write-Output "SQLite version loaded: $version"
        return $true
    }
    catch {
        Write-Warning "SQLite test failed: $_"
        return $false
    }
}

function Test-VCRedistInstalled {
    <#
    .SYNOPSIS
    Checks if Visual C++ Redistributable x64 is installed.
    #>
    try {
        # Check for VC++ Redistributable 2015-2022 (the latest unified version)
        $vcRedist = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue
        
        if ($vcRedist -and $vcRedist.Installed -eq 1) {
            Write-Output "Visual C++ Redistributable x64 is installed (Version: $($vcRedist.Version))"
            return $true
        }
        
        # Also check the WOW6432Node for compatibility
        $vcRedistWow = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" -ErrorAction SilentlyContinue
        
        if ($vcRedistWow -and $vcRedistWow.Installed -eq 1) {
            Write-Output "Visual C++ Redistributable x64 is installed (Version: $($vcRedistWow.Version))"
            return $true
        }
        
        Write-Warning "Visual C++ Redistributable x64 is not installed."
        return $false
    }
    catch {
        Write-Warning "Error checking for VC++ Redistributable: $_"
        return $false
    }
}

function Install-VCRedist {
    <#
    .SYNOPSIS
    Downloads and installs Visual C++ Redistributable x64.
    #>
    param(
        [string]$DownloadPath = "$env:TEMP\vc_redist.x64.exe"
    )
    
    try {
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        
        Write-Output "Downloading Visual C++ Redistributable x64..."
        Write-Output "Source: $vcRedistUrl"
        Write-Output "Destination: $DownloadPath"
        
        # Download using BITS or WebClient
        try {
            Start-BitsTransfer -Source $vcRedistUrl -Destination $DownloadPath -ErrorAction Stop
            Write-Output "Download completed using BITS."
        }
        catch {
            Write-Warning "BITS transfer failed, using WebClient..."
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($vcRedistUrl, $DownloadPath)
            $webClient.Dispose()
            Write-Output "Download completed using WebClient."
        }
        
        # Verify download
        if (-not (Test-Path $DownloadPath)) {
            throw "Downloaded file not found at: $DownloadPath"
        }
        
        $fileSize = (Get-Item $DownloadPath).Length
        if ($fileSize -lt 1MB) {
            throw "Downloaded file is too small ($fileSize bytes). Download may have failed."
        }
        
        Write-Output "Installing Visual C++ Redistributable x64..."
        Write-Output "File size: $fileSize bytes"
        
        # Install silently with /quiet /norestart
        $installProcess = Start-Process -FilePath $DownloadPath -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru
        
        if ($installProcess.ExitCode -eq 0) {
            Write-Output "Visual C++ Redistributable installed successfully."
            return $true
        }
        elseif ($installProcess.ExitCode -eq 3010) {
            Write-Warning "Visual C++ Redistributable installed successfully, but a reboot is required."
            return $true
        }
        else {
            Write-Error "Visual C++ Redistributable installation failed with exit code: $($installProcess.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Error "Error during VC++ Redistributable installation: $_"
        return $false
    }
    finally {
        # Clean up downloaded file
        if (Test-Path $DownloadPath) {
            Remove-Item $DownloadPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Main SQLite Loading Logic
# -------------------------

# Define the path to the SQLite Data
$SQLPath = "$($DestinationPath)\SQLite"

# Verify SQLite files exist
if (-not (Test-Path $SQLPath)) {
    Write-Error "SQLite folder not found at: $SQLPath"
    Write-Error "CRITICAL: Cannot proceed without SQLite files. Exiting installation."
    Stop-Transcript
    exit 1
}

Write-Output "`n========================================="
Write-Output "Preparing SQLite Environment"
Write-Output "=========================================`n"

# Define file paths
$mainDll = Join-Path -Path $SQLPath -ChildPath "System.Data.SQLite.dll"
$nativeDllRoot = Join-Path -Path $SQLPath -ChildPath "SQLite.Interop.dll"

# Verify System.Data.SQLite.dll exists
if (-not (Test-Path $mainDll)) {
    Write-Error "System.Data.SQLite.dll not found at: $mainDll"
    Write-Error "CRITICAL: Required SQLite library missing. Exiting installation."
    Stop-Transcript
    exit 1
}

# Unblock ALL files recursively
Write-Output "Unblocking all SQLite files..."
Get-ChildItem -Path $SQLPath -Recurse -File | ForEach-Object {
    Unblock-File -Path $_.FullName -Confirm:$false
}
Write-Output "All SQLite files unblocked.`n"


# Verify the copy succeeded
if (-not (Test-Path $nativeDllRoot)) {
    Write-Error "Failed to copy SQLite.Interop.dll to root folder"
    Write-Error "CRITICAL: Cannot prepare SQLite environment. Exiting installation."
    Stop-Transcript
    exit 1
}

# Add SQLite paths to environment PATH
$env:PATH = "$SQLPath"
Write-Output "Added SQLite paths to session PATH.`n"

# Attempt to load SQLite
Write-Output "Loading System.Data.SQLite.dll..."
try {
    Add-Type -Path $mainDll
    Write-Output "System.Data.SQLite.dll loaded into session.`n"
}
catch {
    Write-Error "Failed to load System.Data.SQLite.dll: $_"
    Write-Error "CRITICAL: Cannot load SQLite library. Exiting installation."
    Stop-Transcript
    exit 1
}

# Test if SQLite actually works (FIRST ATTEMPT)
Write-Output "Testing SQLite functionality..."
$sqliteWorking = Test-SQLiteLoaded

if ($sqliteWorking) {
    Write-Output "`n========================================="
    Write-Output "SQLite loaded and verified successfully!"
    Write-Output "=========================================`n"
}
else {
    Write-Warning "`nSQLite loaded but cannot access SQLiteConnection."
    Write-Warning "This typically indicates missing Visual C++ Redistributable.`n"
    
    # Check if VC++ Redistributable is installed
    Write-Output "Checking for Visual C++ Redistributable x64..."
    $vcInstalled = Test-VCRedistInstalled
    
    if (-not $vcInstalled) {
        Write-Output "`nVisual C++ Redistributable x64 is NOT installed."
        Write-Output "Attempting to download and install...`n"
        
        $installSuccess = Install-VCRedist
        
        if (-not $installSuccess) {
            Write-Error "`n========================================="
            Write-Error "CRITICAL ERROR: Failed to install Visual C++ Redistributable"
            Write-Error "========================================="
            Write-Error "SQLite requires Visual C++ Redistributable x64 to function."
            Write-Error "Please manually download and install from:"
            Write-Error "https://aka.ms/vs/17/release/vc_redist.x64.exe"
            Write-Error "Then re-run this installation script."
            Write-Error "=========================================`n"
            Stop-Transcript
            exit 1
        }
        
        # VC++ installed, test SQLite again (SECOND ATTEMPT)
        Write-Output "`nVisual C++ Redistributable installed. Testing SQLite again..."
        $sqliteWorking = Test-SQLiteLoaded
        
        if ($sqliteWorking) {
            Write-Output "`n========================================="
            Write-Output "SQLite now working after VC++ installation!"
            Write-Output "=========================================`n"
        }
        else {
            Write-Error "`n========================================="
            Write-Error "CRITICAL ERROR: SQLite still not working"
            Write-Error "========================================="
            Write-Error "Visual C++ Redistributable was installed, but SQLite still cannot load."
            Write-Error "Possible issues:"
            Write-Error "  1. A system reboot may be required"
            Write-Error "  2. SQLite files may be corrupted"
            Write-Error "  3. Additional dependencies may be missing"
            Write-Error ""
            Write-Error "Please try:"
            Write-Error "  1. Reboot the system"
            Write-Error "  2. Re-run this installation script"
            Write-Error "  3. If problem persists, contact support"
            Write-Error "=========================================`n"
            Stop-Transcript
            exit 1
        }
    }
    else {
        # VC++ is installed but SQLite still doesn't work
        Write-Error "`n========================================="
        Write-Error "CRITICAL ERROR: SQLite cannot load"
        Write-Error "========================================="
        Write-Error "Visual C++ Redistributable IS installed, but SQLite still cannot load."
        Write-Error "This indicates a different issue:"
        Write-Error "  1. SQLite files may be corrupted or blocked"
        Write-Error "  2. Insufficient permissions"
        Write-Error "  3. Conflicting DLL versions"
        Write-Error "  4. System may need a reboot"
        Write-Error ""
        Write-Error "Troubleshooting steps:"
        Write-Error "  1. Verify all files in $SQLPath are unblocked"
        Write-Error "  2. Run this script as Administrator"
        Write-Error "  3. Reboot the system and try again"
        Write-Error "  4. Re-download SQLite files"
        Write-Error "=========================================`n"
        Stop-Transcript
        exit 1
    }
}

# Continue with database creation if we reach here
Write-Output "Proceeding with database creation...`n"

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
