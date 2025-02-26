<# 
.SYNOPSIS
    Uploads and configures the Workspace ONE Autorecovery application in Workspace ONE UEM.

.DESCRIPTION
    This script performs the following tasks:
      - Generates the .zip file
      - Calculates a SHA256 hash for a file contained within a ZIP archive.
      - Generates API headers for Workspace ONE UEM.
      - Searches for an existing "Workspace ONE Autorecovery" application.
      - Retrieves the Organization Group's UUID using the provided OGID.
      - Uploads application components (application ZIP, detection script, uninstall script, and, if a new app, the icon).
      - Generates a JSON payload for creating/updating the application.
      - Initiates the application installation via the Workspace ONE UEM API.

.PARAMETER APIEndpoint
    The Workspace ONE UEM API endpoint (e.g., as1831.awmdm.com).

.PARAMETER APIUser
    The API username.

.PARAMETER APIPassword
    The API password.

.PARAMETER APIKey
    The API key (or tenant code).

.PARAMETER OGID
    The organization group ID. This is used to retrieve the group's UUID for API calls.

.EXAMPLE
    Always store the required files (the application folder, detection.ps1, uninstall.ps1 and the icon in the same location as this script)
    .\Upload_to_ws1.ps1  -APIEndpoint "as1831.awmdm.com" -APIUser "admin" -APIPassword "password" -APIKey "ABC123" -OGID "1298"

.Prerequisites 
    Please make sure that you downloaded all required content
    Modify the config.json file that is stored in the application folder to fit your requirements

.NOTES
    Author        : Grischa Ernst
    Date          : 2025-02-15
    Version       : 1.0.0

.LICENSE
    Distributed under the terms specified in the license.md file.
#>

param(
    [string]$APIEndpoint,
    [string]$APIUser,
    [string]$APIPassword,
    [string]$APIKey,
    [string]$OGID
)


##########################################################################################
#                                    Functions

# Function: Create-UEMAPIHeader
# Description: Generates the required API headers for Workspace ONE UEM API calls.
function Create-UEMAPIHeader {
    param(
        [string] $APIUser, 
        [string] $APIPassword,
        [string] $APIKey,
        [string] $ContentType = "json",
        [string] $Accept = "json",
        [int] $APIVersion = 1
    )

    # Generate API credentials (Basic Authentication)
    $UserNameWithPassword = $APIUser + ":" + $APIPassword
    $Encoding = [System.Text.Encoding]::ASCII.GetBytes($UserNameWithPassword)
    $EncodedString = [Convert]::ToBase64String($Encoding)
    $Auth = "Basic $EncodedString"

    # Generate header dictionary
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("aw-tenant-code", $APIKey)
    $headers.Add("Authorization", $Auth)
    $headers.Add("Accept", "application/$Accept;version=$APIVersion")
    $headers.Add("Content-Type", "application/$ContentType")
    return $headers
}

# Function: Increment-Version
# Description: Increments the patch version (x.y.z) of a version string.
function Update-Version {
    param(
        [Parameter(Mandatory)]
        [string]$Version
    )
    $parts = $Version -split "\."
    if ($parts.Count -eq 3) {
        $parts[2] = [int]$parts[2] + 1
        return "$($parts[0]).$($parts[1]).$($parts[2])"
    }
    else {
        # If the version isn't in the expected format, default to 1.0.1.
        return "1.0.1"
    }
}

# Function: New-APIApplicationBody
# Description: Generates the JSON body for creating/updating the application in Workspace ONE UEM.
function New-APIApplicationBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$orgID,
        
        [Parameter(Mandatory)]
        [string]$OGGUID,
        
        [Parameter(Mandatory)]
        [int]$ApplicationBlobID,

        [Parameter(Mandatory)]
        [string]$ApplicationFileName,
        
        [Parameter(Mandatory)]
        [int]$CustomScriptFileBlobId,
       
        [Parameter(Mandatory = $false)]
        [string]$IconBlobUuid,
        
        [Parameter(Mandatory)]
        [int]$UninstallScriptBlob,
        
        [Parameter(Mandatory)]
        [int]$FileSize,
        
        [Parameter(Mandatory)]
        [string]$ExpectedHash,
        
        # Optional parameter for existing application search results.
        [Parameter(Mandatory = $false)]
        $ExistingApplication
    )
    
    # Check if an existing app was found; if so, use its IDs and bump its version.
    if ($ExistingApplication -and $ExistingApplication.Application) {
        $existingApp = $ExistingApplication.Application
        Write-Verbose "Existing app found. Using BundleId '$($existingApp.BundleId)' and Uuid '$($existingApp.Uuid)'."
        if ($existingApp.BundleId -is [System.Array]) {
            # Select the unique GUID(s) and use the first one.
            $bundleId = ($existingApp.BundleId | Select-Object -Unique | Select-Object -First 1)
        }
        else {
            $bundleId = $existingApp.BundleId
        }
        $uuid = $existingApp.Uuid

        # Use the existing ActualFileVersion and bump its patch number.
        $currentVersions = $existingApp.ActualFileVersion
        if ($currentVersions -is [System.Array]) {
            # Convert each version string to a [version] object, sort in descending order, and select the first one.
            $currentVersion = ($currentVersions | ForEach-Object { [version]$_ } | Sort-Object -Descending | Select-Object -First 1).ToString()
        }
        else {
            $currentVersion = $existingApp.ActualFileVersion
        }

        
        if (-not $currentVersion) { $currentVersion = "1.0.0" }
        $newVersion = Update-Version -Version $currentVersion
        $isNewApp = $false
    }
    else {
        Write-Verbose "No existing app found. Generating new IDs and starting with version 1.0.0."
        $bundleId = [guid]::NewGuid().ToString()
        $uuid = [guid]::NewGuid().ToString()
        $newVersion = "1.0.0"
        $isNewApp = $true
    }

    # Build the API body as a PowerShell object.
    $body = @{
        ApplicationName                    = "Workspace ONE Autorecovery"
        BlobId                             = $ApplicationBlobID
        BundleId                           = $bundleId
        BuildVersion                       = $bundleId
        ActualFileVersion                  = $newVersion
        AirwatchAppVersion                 = $newVersion
        FileName                           = $ApplicationFileName
        Status                             = "Active"
        DeviceType                         = 12
        ManagedBy                          = $orgID
        SupportedProcessorArchitecture     = "x86"
        ManagedByUuid                      = $OGGUID
        AppProvisioningProfileUuid         = "00000000-0000-0000-0000-000000000000"
        AssumeManagementOfUserInstalledApp = "No"
        Platform                           = "WinRT"
        SupportedModels                    = @{
            Model = @(
                @{
                    ModelId   = 83
                    ModelName = "Desktop"
                }
            )
        }
        MinimumOperatingSystem             = "Windows 10 (10.0.10240)"
        AppSizeInKB                        = $FileSize
        Comments                           = ""
        ChangeLog                          = ""
        DeploymentOptions                  = @{
            WhenToInstall             = @{
                DataContingencies     = @()
                DiskSpaceRequiredInKb = 0
                DevicePowerRequired   = 0
                RamRequiredInMb       = 0
            }
            HowToInstall              = @{
                InstallContext           = "Device"
                InstallCommand           = "powershell -executionpolicy bypass -file install.ps1 -ExpectedHash $ExpectedHash"
                AdminPrivileges          = "true"
                DeviceRestart            = "DoNotRestart"
                UninstallDeviceRestart   = "DoNotRestart"
                RetryCount               = 0
                RetryIntervalInMinutes   = 5
                InstallTimeoutInMinutes  = 5
                InstallerRebootExitCode  = ""
                InstallerSuccessExitCode = ""
                RestartDeadlineInDays    = 0
            }
            WhenToCallInstallComplete = @{
                UseAdditionalCriteria = "true"
                IdentifyApplicationBy = "UsingCustomScript"
                CustomScript          = @{
                    ScriptType             = "PowerShell"
                    CommandToRunTheScript  = "powershell -executionpolicy bypass -file detection.ps1 -FileHash $ExpectedHash"
                    # API bug: Property name must be "CustomScriptFileBlodId" (note the extra 'd')
                    CustomScriptFileBlodId = $CustomScriptFileBlobId
                    SuccessExitCode        = 0
                }
            }
        }
        FilesOptions                       = @{
            AppDependenciesList         = @()
            AppTransformsList           = @()
            AppPatchesList              = @()
            ApplicationUnInstallProcess = @{
                UseCustomScript = $true
                CustomScript    = @{
                    CustomScriptType      = "Upload"
                    UninstallCommand      = "powershell -executionpolicy bypass -file uninstall.ps1 -InstallDir C:\Windows\UEMRecovery"
                    UninstallScriptBlobId = $UninstallScriptBlob
                }
            }
        }
    }

    # Add the icon property only if this is a new app.
    if ($isNewApp) {
        $body.IconBlobUuId = $IconBlobUuid
    }
    
    # Convert the object to JSON (with sufficient depth for nested objects) and return.
    $json = $body | ConvertTo-Json -Depth 10
    return $json
}

# Function: Get-ZipFileEntryHash
# Description: Computes the hash (SHA256, SHA1, or MD5) of a specified file entry within a ZIP archive without extracting it.
function Get-ZipFileEntryHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipFilePath,

        [Parameter(Mandatory = $true)]
        [string]$EntryName,

        [Parameter()]
        [ValidateSet("SHA256", "SHA1", "MD5")]
        [string]$Algorithm = "SHA256"
    )

    # Load required .NET assembly for ZIP file handling.
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Open the ZIP archive.
    $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($ZipFilePath)
    try {
        # Locate the specified entry.
        $entry = $zipArchive.Entries | Where-Object { $_.FullName -eq $EntryName }
        if (-not $entry) {
            throw "Entry '$EntryName' not found in ZIP file '$ZipFilePath'."
        }

        # Open the entry stream and compute the hash.
        $entryStream = $entry.Open()
        try {
            switch ($Algorithm.ToUpper()) {
                "SHA256" { $hasher = [System.Security.Cryptography.SHA256]::Create() }
                "SHA1" { $hasher = [System.Security.Cryptography.SHA1]::Create() }
                "MD5" { $hasher = [System.Security.Cryptography.MD5]::Create() }
            }
            $hashBytes = $hasher.ComputeHash($entryStream)
            $hashString = [BitConverter]::ToString($hashBytes) -replace '-', ''
            return $hashString
        }
        finally {
            $entryStream.Dispose()
        }
    }
    finally {
        $zipArchive.Dispose()
    }
}


# Function: New-ZipFile
# Description: This function uses Compress-Archive to create a ZIP archive that contains a list of pre-defined files.
function New-ZipFile {
  
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Files = @()
    )

    # Remove the existing ZIP file if it exists.
    if (Test-Path $DestinationPath) {
        Remove-Item $DestinationPath -Force
    }
    
    try {
        Compress-Archive -Path $Files -DestinationPath $DestinationPath -Force
        Write-Output "ZIP file created successfully at: $DestinationPath"
    }
    catch {
        Write-Error "Failed to create ZIP file: $_"
    }
}


##########################################################################################
#                                    Start Script

# Determine base path for files (use SourcePath if provided; otherwise, use the script directory)
$basePath = if ($SourcePath) { $SourcePath } else { $PSScriptRoot }

# Generate the .zip
$ZipFiles = Get-ChildItem -Path "$($PSScriptRoot)\Application" 
New-ZipFile -DestinationPath "$($PSScriptRoot)\WorkspaceONEAutorecovery.zip" -Files $ZipFiles.fullname

# Calculate the SHA256 hash for a specific file entry within the ZIP.
$zipPath = Join-Path $PSScriptRoot "WorkspaceONEAUtorecovery.zip"
$fileInsideZip = "HubHealthEvaluation.ps1"  # The internal path as stored in the ZIP.
$hashValue = Get-ZipFileEntryHash -ZipFilePath $zipPath -EntryName $fileInsideZip -Algorithm "SHA256"
Write-Output "The hash for '$fileInsideZip' is: $hashValue"

# Generate the API header for REST calls.
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey 

# Search for an existing "Workspace ONE Autorecovery" application.
$searchUrl = "https://$APIEndpoint/api/mam/apps/search?type=App&applicationtype=Internal&applicationname=Workspace%20One%20Autorecovery&status=Active"
$ExistingApplication = Invoke-RestMethod -Uri $searchUrl -Method 'GET' -Headers $header -Verbose

# Retrieve Organization Group details (to get the OG UUID) using the provided OGID.
$url = "https://$APIEndpoint/API/system/groups/$OGID"
$OGDetails = Invoke-RestMethod -Uri $url -Method 'GET' -Headers $header 
$OGGUID = $OGDetails.uuid

# Define filenames for application components.
$ApplicationFileName = "WorkspaceONEAUtorecovery.zip"
$DetectionFileName = "detection.ps1"
$IconFileName = "WorkspaceONERecoverySolution.jpg"
$UninstallScriptFileName = "uninstall.ps1"

# Generate full file paths.
$ApplicationFile = Join-Path $basePath $ApplicationFileName
$DetectionFile = Join-Path $basePath $DetectionFileName
$IconFile = Join-Path $basePath $IconFileName
$UninstallScriptFile = Join-Path $basePath $UninstallScriptFileName

# Get the file size (in KB) of the application ZIP.
$fileInfo = Get-Item $ApplicationFile
$fileSizeKB = [math]::Round($fileInfo.Length / 1KB, 0)
Write-Output "$fileSizeKB KB"

# Generate an octet-stream header for file uploads.
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey -ContentType "octet-stream"

# Upload the application ZIP file.
try {
    $url = "https://$APIEndpoint/api/mam/blobs/uploadblob?filename=$ApplicationFileName&organizationgroupid=$OGID&moduleType=Application"
    $AppUpload = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $header -InFile $ApplicationFile
    Write-Host "Application file uploaded successfully: $ApplicationFileName" -ForegroundColor Green
}
catch {
    Write-Error "Error uploading application file ($ApplicationFileName): $($_.Exception.Message)"
}

# Upload the detection script.
try {
    $url = "https://$APIEndpoint/api/mam/blobs/uploadblob?filename=$DetectionFileName&organizationgroupid=$OGID&moduleType=Application"
    $DetectionScriptUpload = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $header -InFile $DetectionFile
    Write-Host "Detection script uploaded successfully: $DetectionFileName" -ForegroundColor Green
}
catch {
    Write-Error "Error uploading detection script ($DetectionFileName): $($_.Exception.Message)"
}

# Upload the uninstall script.
try {
    $url = "https://$APIEndpoint/api/mam/blobs/uploadblob?filename=$UninstallScriptFileName&organizationgroupid=$OGID&moduleType=Application"
    $UninstallScriptUpload = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $header -InFile $UninstallScriptFile
    Write-Host "Uninstallation script uploaded successfully: $UninstallScriptFileName" -ForegroundColor Green
}
catch {
    Write-Error "Error uploading uninstall script ($UninstallScriptFileName): $($_.Exception.Message)"
}

# Upload the icon file only if the application does not already exist.
if (-not $ExistingApplication) {
    try {
        $url = "https://$APIEndpoint/api/mam/blobs/uploadblob?filename=$IconFileName&organizationgroupid=$OGID&moduleType=Application"
        $IconUpload = Invoke-RestMethod -Uri $url -Method 'POST' -Headers $header -InFile $IconFile
        Write-Host "Icon file uploaded successfully: $IconFileName" -ForegroundColor Green
    }
    catch {
        Write-Error "Error uploading icon file ($IconFileName): $($_.Exception.Message)"
    }
}

# Generate the JSON body for creating/updating the application.
$jsonBody = New-APIApplicationBody -orgID $OGID `
    -OGGUID $OGGUID `
    -ApplicationBlobID $AppUpload.Value `
    -CustomScriptFileBlobId $DetectionScriptUpload.Value `
    -IconBlobUuid ($IconUpload.uuid) `
    -UninstallScriptBlob $UninstallScriptUpload.Value `
    -FileSize $fileSizeKB `
    -ExpectedHash $hashValue `
    -ApplicationFileName $ApplicationFileName `
    -ExistingApplication $ExistingApplication

# Generate header for JSON submission (defaults to Content-Type application/json).
$header = Create-UEMAPIHeader -APIUser $APIUser -APIPassword $APIPassword -APIKey $APIKey 

# Create/update the application by initiating the installation via the API.
$url = "https://$APIEndpoint/api/mam/apps/internal/begininstall"
Invoke-RestMethod -Uri $url -Method 'POST' -Headers $header -Body $jsonBody -Verbose
