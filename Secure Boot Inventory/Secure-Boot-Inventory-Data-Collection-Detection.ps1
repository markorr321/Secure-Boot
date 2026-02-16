<#
.SYNOPSIS
    Detects Secure Boot certificate update status for fleet-wide monitoring.

.DESCRIPTION
    This detection script collects Secure Boot status, certificate update registry values,
    and device information. It outputs a JSON string for monitoring and reporting.

    Compatible with Intune Remediations, GPO-based collection, and other management tools.
    No remediation script is needed — this is monitoring only.

    Exit 0 = "Without issue"  (certificates updated)
    Exit 1 = "With issue"     (certificates not updated — informational only)

    Source: https://support.microsoft.com/en-us/topic/sample-secure-boot-inventory-data-collection-script-d02971d2-d4b5-42c9-b58a-8527f0ffa30b
    KB ID: 5072718

.NOTES
    Registry paths per https://aka.ms/securebootplaybook:
      HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot
      HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

# =============================================================================
# Logging Configuration
# =============================================================================

# Create timestamped log folder and file
$ScriptName = "Secure-Boot-Inventory-Detection"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$LogFolder = Join-Path -Path "C:\Windows\Temp" -ChildPath "${ScriptName}_${Timestamp}"
$LogFile = Join-Path -Path $LogFolder -ChildPath "logfile_${Timestamp}.log"

# Create log directory if it doesn't exist
try {
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Warning "Failed to create log folder: $_"
}

# Logging function with plain English output
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR','SECTION')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"

    # Color coding for console output
    $Color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        'SECTION' { 'Cyan' }
        default   { 'White' }
    }

    # Write to console (unless suppressed)
    if (-not $NoConsole) {
        Write-Host $LogEntry -ForegroundColor $Color
    }

    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if log file is inaccessible
    }
}

# Initialize log file
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "Secure Boot Certificate Detection Script" -Level SECTION
Write-Log -Message "Started: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level SECTION
Write-Log -Message "Log File: $LogFile" -Level INFO
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

# 1. HostName
# PS Version: All | Admin: No | System Requirements: None
Write-Log -Message "STEP 1: Collecting Device Hostname" -Level SECTION
try {
    $hostname = $env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($hostname)) {
        Write-Log -Message "Unable to determine device hostname - value is empty" -Level WARNING
        $hostname = "Unknown"
    } else {
        Write-Log -Message "Device hostname successfully retrieved: $hostname" -Level SUCCESS
    }
} catch {
    Write-Log -Message "ERROR retrieving hostname: $_" -Level ERROR
    $hostname = "Error"
}
Write-Log -Message "Result: Hostname = $hostname" -Level INFO
Write-Log -Message ""

# 2. CollectionTime
# PS Version: All | Admin: No | System Requirements: None
Write-Log -Message "STEP 2: Recording Collection Timestamp" -Level SECTION
try {
    $collectionTime = Get-Date
    if ($null -eq $collectionTime) {
        Write-Log -Message "Failed to retrieve current date/time" -Level WARNING
        $collectionTime = "Unknown"
    } else {
        Write-Log -Message "Timestamp captured: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level SUCCESS
    }
} catch {
    Write-Log -Message "ERROR retrieving date/time: $_" -Level ERROR
    $collectionTime = "Error"
}
Write-Log -Message "Result: Collection Time = $collectionTime" -Level INFO
Write-Log -Message ""

# Registry: Secure Boot Main Key (3 values)
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "SECURE BOOT STATUS DETECTION" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# 3. SecureBootEnabled
# PS Version: 3.0+ | Admin: May be required | System Requirements: UEFI/Secure Boot capable system
Write-Log -Message "STEP 3: Checking if Secure Boot is Enabled" -Level SECTION
Write-Log -Message "Attempting to query Secure Boot status using Confirm-SecureBootUEFI cmdlet..." -Level INFO
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($secureBootEnabled) {
        Write-Log -Message "SUCCESS: Secure Boot is ENABLED on this device" -Level SUCCESS
        Write-Log -Message "This device is protected by UEFI Secure Boot" -Level INFO
    } else {
        Write-Log -Message "WARNING: Secure Boot is DISABLED on this device" -Level WARNING
        Write-Log -Message "This device may be vulnerable to boot-level attacks" -Level WARNING
    }
} catch {
    Write-Log -Message "Unable to query Secure Boot via cmdlet: $_" -Level WARNING
    Write-Log -Message "Attempting fallback method using registry..." -Level INFO
    # Try registry fallback
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
        $secureBootEnabled = [bool]$regValue.UEFISecureBootEnabled
        if ($secureBootEnabled) {
            Write-Log -Message "SUCCESS: Secure Boot is ENABLED (confirmed via registry)" -Level SUCCESS
        } else {
            Write-Log -Message "Secure Boot is DISABLED (confirmed via registry)" -Level WARNING
        }
    } catch {
        Write-Log -Message "ERROR: Cannot determine Secure Boot status" -Level ERROR
        Write-Log -Message "This system may not support UEFI/Secure Boot or may be running legacy BIOS" -Level WARNING
        $secureBootEnabled = $null
    }
}
Write-Log -Message "Result: Secure Boot Enabled = $secureBootEnabled" -Level INFO
Write-Log -Message ""

# 4. HighConfidenceOptOut
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop
    $highConfidenceOptOut = $regValue.HighConfidenceOptOut
    Write-Host "High Confidence Opt Out: $highConfidenceOptOut"
} catch {
    Write-Warning "HighConfidenceOptOut registry key not found or inaccessible"
    $highConfidenceOptOut = $null
    Write-Host "High Confidence Opt Out: Not Available"
}

# 5. AvailableUpdates
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop
    $availableUpdates = $regValue.AvailableUpdates
    if ($null -ne $availableUpdates) {
        # Convert to hexadecimal format
        $availableUpdatesHex = "0x{0:X}" -f $availableUpdates
        Write-Host "Available Updates: $availableUpdatesHex"
    } else {
        Write-Host "Available Updates: Not Available"
    }
} catch {
    Write-Warning "AvailableUpdates registry key not found or inaccessible"
    $availableUpdates = $null
    Write-Host "Available Updates: Not Available"
}

# Registry: Servicing Key (3 values)
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "CERTIFICATE UPDATE STATUS CHECK" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# 6. UEFICA2023Status
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 6: Checking Windows UEFI CA 2023 Certificate Status" -Level SECTION
Write-Log -Message "This is the PRIMARY compliance indicator for Secure Boot certificate updates" -Level INFO
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop
    $uefica2023Status = $regValue.UEFICA2023Status

    switch ($uefica2023Status) {
        "Updated" {
            Write-Log -Message "EXCELLENT: Windows UEFI CA 2023 certificates are UPDATED" -Level SUCCESS
            Write-Log -Message "This device has the latest Secure Boot certificates installed" -Level SUCCESS
            Write-Log -Message "Device is COMPLIANT with Secure Boot certificate requirements" -Level SUCCESS
        }
        "NotStarted" {
            Write-Log -Message "ATTENTION: Certificate update has NOT been started" -Level WARNING
            Write-Log -Message "This device needs the Secure Boot certificate update applied" -Level WARNING
            Write-Log -Message "Remediation script should set AvailableUpdates=0x5944 to trigger update" -Level INFO
        }
        "InProgress" {
            Write-Log -Message "INFO: Certificate update is IN PROGRESS" -Level INFO
            Write-Log -Message "A reboot may be required to complete the update process" -Level INFO
        }
        "Failed" {
            Write-Log -Message "ERROR: Certificate update has FAILED" -Level ERROR
            Write-Log -Message "Check Event ID 1808 in System log for failure details" -Level ERROR
        }
        default {
            Write-Log -Message "Status: $uefica2023Status" -Level INFO
        }
    }
} catch {
    Write-Log -Message "WARNING: Cannot read UEFICA2023Status from registry" -Level WARNING
    Write-Log -Message "Registry path may not exist yet (normal for devices that haven't attempted update)" -Level INFO
    $uefica2023Status = $null
}
Write-Log -Message "Result: UEFI CA 2023 Status = $uefica2023Status" -Level INFO
Write-Log -Message ""

# 7. UEFICA2023Error
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop
    $uefica2023Error = $regValue.UEFICA2023Error
    Write-Host "UEFI CA 2023 Error: $uefica2023Error"
} catch {
    Write-Warning "UEFICA2023Error registry key not found or inaccessible"
    $uefica2023Error = $null
    Write-Host "UEFI CA 2023 Error: Not Available"
}

# 9. UEFICA2023ErrorEvent
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop
    $uefica2023ErrorEvent = $regValue.UEFICA2023ErrorEvent
    Write-Host "UEFI CA 2023 Error Event: $uefica2023ErrorEvent"
} catch {
    $uefica2023ErrorEvent = $null
    Write-Host "UEFI CA 2023 Error Event: Not Available"
}

# Registry: Device Attributes (7 values)

# 10. OEMManufacturerName
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop
    $oemManufacturerName = $regValue.OEMManufacturerName
    if ([string]::IsNullOrEmpty($oemManufacturerName)) {
        Write-Warning "OEMManufacturerName is empty"
        $oemManufacturerName = "Unknown"
    }
    Write-Host "OEM Manufacturer Name: $oemManufacturerName"
} catch {
    Write-Warning "OEMManufacturerName registry key not found or inaccessible"
    $oemManufacturerName = $null
    Write-Host "OEM Manufacturer Name: Not Available"
}

# 10. OEMModelSystemFamily
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelSystemFamily -ErrorAction Stop
    $oemModelSystemFamily = $regValue.OEMModelSystemFamily
    if ([string]::IsNullOrEmpty($oemModelSystemFamily)) {
        Write-Warning "OEMModelSystemFamily is empty"
        $oemModelSystemFamily = "Unknown"
    }
    Write-Host "OEM Model System Family: $oemModelSystemFamily"
} catch {
    Write-Warning "OEMModelSystemFamily registry key not found or inaccessible"
    $oemModelSystemFamily = $null
    Write-Host "OEM Model System Family: Not Available"
}

# 11. OEMModelNumber
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelNumber -ErrorAction Stop
    $oemModelNumber = $regValue.OEMModelNumber
    if ([string]::IsNullOrEmpty($oemModelNumber)) {
        Write-Warning "OEMModelNumber is empty"
        $oemModelNumber = "Unknown"
    }
    Write-Host "OEM Model Number: $oemModelNumber"
} catch {
    Write-Warning "OEMModelNumber registry key not found or inaccessible"
    $oemModelNumber = $null
    Write-Host "OEM Model Number: Not Available"
}

# 12. FirmwareVersion
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareVersion -ErrorAction Stop
    $firmwareVersion = $regValue.FirmwareVersion
    if ([string]::IsNullOrEmpty($firmwareVersion)) {
        Write-Warning "FirmwareVersion is empty"
        $firmwareVersion = "Unknown"
    }
    Write-Host "Firmware Version: $firmwareVersion"
} catch {
    Write-Warning "FirmwareVersion registry key not found or inaccessible"
    $firmwareVersion = $null
    Write-Host "Firmware Version: Not Available"
}

# 13. FirmwareReleaseDate
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareReleaseDate -ErrorAction Stop
    $firmwareReleaseDate = $regValue.FirmwareReleaseDate
    if ([string]::IsNullOrEmpty($firmwareReleaseDate)) {
        Write-Warning "FirmwareReleaseDate is empty"
        $firmwareReleaseDate = "Unknown"
    }
    Write-Host "Firmware Release Date: $firmwareReleaseDate"
} catch {
    Write-Warning "FirmwareReleaseDate registry key not found or inaccessible"
    $firmwareReleaseDate = $null
    Write-Host "Firmware Release Date: Not Available"
}

# 14. OSArchitecture
# PS Version: All | Admin: No | System Requirements: None
try {
    $osArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        # Try registry fallback
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OSArchitecture -ErrorAction Stop
        $osArchitecture = $regValue.OSArchitecture
    }
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        Write-Warning "OSArchitecture could not be determined"
        $osArchitecture = "Unknown"
    }
    Write-Host "OS Architecture: $osArchitecture"
} catch {
    Write-Warning "Error retrieving OSArchitecture: $_"
    $osArchitecture = "Unknown"
    Write-Host "OS Architecture: $osArchitecture"
}

# 15. CanAttemptUpdateAfter (FILETIME)
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name CanAttemptUpdateAfter -ErrorAction Stop
    $canAttemptUpdateAfter = $regValue.CanAttemptUpdateAfter
    # Convert FILETIME to UTC DateTime — registry stores as REG_BINARY (byte[]) or REG_QWORD (long)
    if ($null -ne $canAttemptUpdateAfter) {
        try {
            if ($canAttemptUpdateAfter -is [byte[]]) {
                $fileTime = [BitConverter]::ToInt64($canAttemptUpdateAfter, 0)
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($fileTime).ToUniversalTime()
            } elseif ($canAttemptUpdateAfter -is [long]) {
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($canAttemptUpdateAfter).ToUniversalTime()
            }
        } catch {
            Write-Warning "Could not convert CanAttemptUpdateAfter FILETIME to DateTime"
        }
    }
    Write-Host "Can Attempt Update After: $canAttemptUpdateAfter"
} catch {
    Write-Warning "CanAttemptUpdateAfter registry key not found or inaccessible"
    $canAttemptUpdateAfter = $null
    Write-Host "Can Attempt Update After: Not Available"
}

# Event Logs: System Log (5 values)

# 16-20. Event Log queries
# PS Version: 3.0+ | Admin: May be required for System log | System Requirements: None
try {
    $allEventIds = @(1801, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 20 -ErrorAction Stop)

    if ($events.Count -eq 0) {
        Write-Warning "No Secure Boot events (1801/1808) found in System log"
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $event1801Count = 0
        $event1808Count = 0
        Write-Host "Latest Event ID: Not Available"
        Write-Host "Bucket ID: Not Available"
        Write-Host "Confidence: Not Available"
        Write-Host "Event 1801 Count: 0"
        Write-Host "Event 1808 Count: 0"
    } else {
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            Write-Warning "Could not determine latest event"
            $latestEventId = $null
            Write-Host "Latest Event ID: Not Available"
        } else {
            $latestEventId = $latestEvent.Id
            Write-Host "Latest Event ID: $latestEventId"
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
                Write-Host "Bucket ID: $bucketId"
            } else {
                Write-Warning "BucketId not found in event message"
                $bucketId = $null
                Write-Host "Bucket ID: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract BucketId"
            $bucketId = $null
            Write-Host "Bucket ID: Not Available"
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
                Write-Host "Confidence: $confidence"
            } else {
                Write-Warning "Confidence level not found in event message"
                $confidence = $null
                Write-Host "Confidence: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract Confidence"
            $confidence = $null
            Write-Host "Confidence: Not Available"
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count
        Write-Host "Event 1801 Count: $event1801Count"

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        Write-Host "Event 1808 Count: $event1808Count"
    }
} catch {
    Write-Warning "Error retrieving event logs. May require administrator privileges: $_"
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $event1801Count = 0
    $event1808Count = 0
    Write-Host "Latest Event ID: Error"
    Write-Host "Bucket ID: Error"
    Write-Host "Confidence: Error"
    Write-Host "Event 1801 Count: 0"
    Write-Host "Event 1808 Count: 0"
}

# WMI/CIM Queries (4 values)

# 21. OSVersion
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or [string]::IsNullOrEmpty($osInfo.Version)) {
        Write-Warning "Could not retrieve OS version"
        $osVersion = "Unknown"
    } else {
        $osVersion = $osInfo.Version
    }
    Write-Host "OS Version: $osVersion"
} catch {
    Write-Warning "Error retrieving OS version: $_"
    $osVersion = "Unknown"
    Write-Host "OS Version: $osVersion"
}

# 22. LastBootTime
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or $null -eq $osInfo.LastBootUpTime) {
        Write-Warning "Could not retrieve last boot time"
        $lastBootTime = $null
        Write-Host "Last Boot Time: Not Available"
    } else {
        $lastBootTime = $osInfo.LastBootUpTime
        Write-Host "Last Boot Time: $lastBootTime"
    }
} catch {
    Write-Warning "Error retrieving last boot time: $_"
    $lastBootTime = $null
    Write-Host "Last Boot Time: Not Available"
}

# 23. BaseBoardManufacturer
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Manufacturer)) {
        Write-Warning "Could not retrieve baseboard manufacturer"
        $baseBoardManufacturer = "Unknown"
    } else {
        $baseBoardManufacturer = $baseBoard.Manufacturer
    }
    Write-Host "Baseboard Manufacturer: $baseBoardManufacturer"
} catch {
    Write-Warning "Error retrieving baseboard manufacturer: $_"
    $baseBoardManufacturer = "Unknown"
    Write-Host "Baseboard Manufacturer: $baseBoardManufacturer"
}

# 24. BaseBoardProduct
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Product)) {
        Write-Warning "Could not retrieve baseboard product"
        $baseBoardProduct = "Unknown"
    } else {
        $baseBoardProduct = $baseBoard.Product
    }
    Write-Host "Baseboard Product: $baseBoardProduct"
} catch {
    Write-Warning "Error retrieving baseboard product: $_"
    $baseBoardProduct = "Unknown"
    Write-Host "Baseboard Product: $baseBoardProduct"
}

# =============================================================================
# Remediation Detection - Status Output & Exit Code
# =============================================================================

<#
This section assembles all collected data into a structured JSON output and determines
the compliance status of the device based on Secure Boot certificate update state.

PURPOSE:
    - Aggregate all 24 inventory data points into a single status object
    - Convert the object to compressed JSON for easy parsing by monitoring systems
    - Determine if the device has successfully applied Secure Boot certificate updates
    - Return appropriate exit code for Intune Remediation detection logic

EXIT CODE LOGIC:
    Exit 0 (Compliant - "Without issue"):
        - Secure Boot is ENABLED on the device, AND
        - Windows UEFI CA 2023 Status equals "Updated"
        - This indicates certificates have been successfully deployed

    Exit 1 (Non-compliant - "With issue"):
        - Secure Boot is DISABLED, OR
        - Windows UEFI CA 2023 Status is NOT "Updated"
        - This is informational only - triggers remediation script to set AvailableUpdates=0x5944

JSON OUTPUT:
    The status object is output as compressed JSON containing all registry values, event log
    data, and system information. This can be ingested by Log Analytics, Power BI dashboards,
    custom compliance policies, or other monitoring solutions for fleet-wide visibility into
    Secure Boot certificate deployment status.

USAGE IN INTUNE PROACTIVE REMEDIATIONS:
    1. This script runs as the DETECTION script
    2. If Exit 1 is returned, Intune triggers the REMEDIATION script
    3. Remediation script sets registry key to initiate certificate update
    4. Device reboots and Windows applies the certificate updates
    5. Next detection run confirms Exit 0 (compliant state)
#>

# Build status object from all collected inventory data
$status = [ordered]@{
    UEFICA2023Status           = $uefica2023Status
    UEFICA2023Error            = $uefica2023Error
    UEFICA2023ErrorEvent       = $uefica2023ErrorEvent
    AvailableUpdates           = if ($null -ne $availableUpdates) { $availableUpdatesHex } else { $null }
    Hostname                   = $hostname
    CollectionTime             = if ($collectionTime -is [datetime]) { $collectionTime.ToString("o") } else { "$collectionTime" }
    SecureBootEnabled          = $secureBootEnabled
    HighConfidenceOptOut       = $highConfidenceOptOut
    OEMManufacturerName        = $oemManufacturerName
    OEMModelSystemFamily       = $oemModelSystemFamily
    OEMModelNumber             = $oemModelNumber
    FirmwareVersion            = $firmwareVersion
    FirmwareReleaseDate        = $firmwareReleaseDate
    OSArchitecture             = $osArchitecture
    CanAttemptUpdateAfter      = if ($canAttemptUpdateAfter -is [datetime]) { $canAttemptUpdateAfter.ToString("o") } else { "$canAttemptUpdateAfter" }
    LatestEventId              = $latestEventId
    BucketId                   = $bucketId
    Confidence                 = $confidence
    Event1801Count             = $event1801Count
    Event1808Count             = $event1808Count
    OSVersion                  = $osVersion
    LastBootTime               = if ($lastBootTime -is [datetime]) { $lastBootTime.ToString("o") } else { "$lastBootTime" }
    BaseBoardManufacturer      = $baseBoardManufacturer
    BaseBoardProduct           = $baseBoardProduct
}

# Output the status - For data aggregation
$jsonOutput = $status | ConvertTo-Json -Compress
Write-Output $jsonOutput

# Log the JSON output
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "JSON OUTPUT FOR DATA COLLECTION" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message $jsonOutput -Level INFO
Write-Log -Message ""

# =============================================================================
# COMPLIANCE SUMMARY & DECISION
# =============================================================================

Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "COMPLIANCE ASSESSMENT" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

# Detailed compliance analysis
Write-Log -Message "Analyzing device compliance status..." -Level INFO
Write-Log -Message ""

# Check 1: Secure Boot Status
if ($secureBootEnabled) {
    Write-Log -Message "✓ Secure Boot Status: ENABLED" -Level SUCCESS
    Write-Log -Message "  Device has UEFI Secure Boot active" -Level INFO
} elseif ($null -eq $secureBootEnabled) {
    Write-Log -Message "✗ Secure Boot Status: UNKNOWN" -Level WARNING
    Write-Log -Message "  Cannot determine if Secure Boot is supported/enabled" -Level WARNING
} else {
    Write-Log -Message "✗ Secure Boot Status: DISABLED" -Level ERROR
    Write-Log -Message "  Device is NOT protected by Secure Boot" -Level ERROR
}
Write-Log -Message ""

# Check 2: Certificate Update Status
if ($uefica2023Status -eq "Updated") {
    Write-Log -Message "✓ Certificate Status: UPDATED" -Level SUCCESS
    Write-Log -Message "  Windows UEFI CA 2023 certificates are installed" -Level INFO
} elseif ($uefica2023Status -eq "NotStarted") {
    Write-Log -Message "✗ Certificate Status: NOT STARTED" -Level WARNING
    Write-Log -Message "  Certificates have not been updated yet" -Level WARNING
} elseif ($uefica2023Status -eq "InProgress") {
    Write-Log -Message "⚠ Certificate Status: IN PROGRESS" -Level INFO
    Write-Log -Message "  Certificate update is currently being applied" -Level INFO
} elseif ($uefica2023Status -eq "Failed") {
    Write-Log -Message "✗ Certificate Status: FAILED" -Level ERROR
    Write-Log -Message "  Certificate update encountered an error" -Level ERROR
} else {
    Write-Log -Message "✗ Certificate Status: UNAVAILABLE" -Level WARNING
    Write-Log -Message "  Status: $uefica2023Status" -Level INFO
}
Write-Log -Message ""

# Final Compliance Decision
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "FINAL COMPLIANCE DECISION" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

if ($secureBootEnabled -and $uefica2023Status -eq "Updated") {
    Write-Log -Message "RESULT: COMPLIANT ✓" -Level SUCCESS
    Write-Log -Message ""
    Write-Log -Message "This device meets all Secure Boot certificate requirements:" -Level SUCCESS
    Write-Log -Message "  • Secure Boot is enabled" -Level SUCCESS
    Write-Log -Message "  • Windows UEFI CA 2023 certificates are updated" -Level SUCCESS
    Write-Log -Message "  • Device is protected against boot-level threats" -Level SUCCESS
    Write-Log -Message ""
    Write-Log -Message "Exit Code: 0 (No remediation needed)" -Level SUCCESS
    Write-Log -Message "Completed: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level INFO
    Write-Log -Message "========================================" -Level SECTION
    exit 0  # Without issue
} else {
    Write-Log -Message "RESULT: NON-COMPLIANT ✗" -Level WARNING
    Write-Log -Message ""
    Write-Log -Message "This device does NOT meet Secure Boot certificate requirements" -Level WARNING
    Write-Log -Message ""
    Write-Log -Message "Issues identified:" -Level WARNING
    if (-not $secureBootEnabled) {
        Write-Log -Message "  • Secure Boot is NOT enabled or cannot be verified" -Level WARNING
    }
    if ($uefica2023Status -ne "Updated") {
        Write-Log -Message "  • Windows UEFI CA 2023 certificates are NOT updated (Status: $uefica2023Status)" -Level WARNING
    }
    Write-Log -Message ""
    Write-Log -Message "RECOMMENDED ACTIONS:" -Level INFO

    # Specific guidance if Secure Boot is disabled
    if (-not $secureBootEnabled) {
        Write-Log -Message ""
        Write-Log -Message "⚠ CRITICAL PREREQUISITE: Secure Boot Must Be Enabled First!" -Level ERROR
        Write-Log -Message ""
        Write-Log -Message "Certificate updates REQUIRE Secure Boot to be enabled in the device firmware." -Level WARNING
        Write-Log -Message "The remediation script will NOT work until Secure Boot is enabled." -Level WARNING
        Write-Log -Message ""
        Write-Log -Message "Methods to Enable Secure Boot:" -Level INFO
        Write-Log -Message ""
        Write-Log -Message "OPTION A - Manual Enablement (Physical Access Required):" -Level INFO
        Write-Log -Message "  1. Restart the device and enter BIOS/UEFI setup during boot:" -Level INFO
        Write-Log -Message "     • Dell: Press F2 or F12" -Level INFO
        Write-Log -Message "     • HP: Press F10 or Esc" -Level INFO
        Write-Log -Message "     • Lenovo: Press F1 or Enter" -Level INFO
        Write-Log -Message "     • Surface: Hold Volume Up + Power button" -Level INFO
        Write-Log -Message "  2. Navigate to Security or Boot settings" -Level INFO
        Write-Log -Message "  3. Set Secure Boot to ENABLED" -Level INFO
        Write-Log -Message "  4. Save changes and exit (usually F10)" -Level INFO
        Write-Log -Message ""
        Write-Log -Message "OPTION B - Automated with OEM Tools (Recommended for Fleet):" -Level INFO
        Write-Log -Message "  • Dell: Use Dell Command | Configure (cctk.exe --secureboot=enable)" -Level INFO
        Write-Log -Message "  • HP: Use HP BIOS Configuration Utility (BCU)" -Level INFO
        Write-Log -Message "  • Lenovo: Use Lenovo BIOS WMI interface or Think BIOS Config Tool" -Level INFO
        Write-Log -Message ""
        Write-Log -Message "OPTION C - Intune Configuration Policy:" -Level INFO
        Write-Log -Message "  • Deploy Device Firmware Configuration Interface (DFCI) policy" -Level INFO
        Write-Log -Message "  • Use OEM-specific Configuration Service Provider (CSP)" -Level INFO
        Write-Log -Message ""
        Write-Log -Message "After enabling Secure Boot, proceed with steps below:" -Level INFO
    }

    Write-Log -Message ""
    Write-Log -Message "Standard Remediation Steps:" -Level INFO
    Write-Log -Message "  1. Ensure Secure Boot is enabled in BIOS/UEFI firmware" -Level INFO
    Write-Log -Message "  2. Run the remediation script (Deploy-SecureBootCert-SelfRollout.ps1)" -Level INFO
    Write-Log -Message "  3. Reboot the device to apply certificate updates" -Level INFO
    Write-Log -Message "  4. Re-run this detection script to verify compliance" -Level INFO
    Write-Log -Message ""
    Write-Log -Message "Exit Code: 1 (Remediation required)" -Level WARNING
    Write-Log -Message "Completed: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level INFO
    Write-Log -Message "========================================" -Level SECTION
    exit 1  # With issue
}