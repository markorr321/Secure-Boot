<#
.SYNOPSIS
    Detects Secure Boot certificate update status for fleet-wide monitoring.

.DESCRIPTION
    This detection script collects Secure Boot status, certificate update registry values,
    and device information. It outputs a JSON string for monitoring and reporting.

    Compatible with Intune Remediations, GPO-based collection, and other management tools.
    No remediation script is needed - this is monitoring only.

    Exit 0 = "Without issue"  (certificates updated)
    Exit 1 = "With issue"     (certificates not updated - informational only)

.PARAMETER OutputPath
    Optional. Path to a folder where the JSON file will be saved.
    If provided, saves HOSTNAME_latest.json to this folder.
    If not provided, outputs JSON to stdout (original behavior).

.EXAMPLE
    # Output to stdout (Intune/SCCM detection)
    .\Detect-SecureBootCertUpdateStatus.ps1

.EXAMPLE
    # Save to network share (GPO deployment)
    .\Detect-SecureBootCertUpdateStatus.ps1 -OutputPath "\\server\SecureBootLogs$"

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
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# =============================================================================
# Logging Configuration
# =============================================================================

# Create timestamped log folder and file
$ScriptName = "PAM - Secure Boot - UEFI CA 2023 Inventory Collection"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$LogFolder = Join-Path -Path $env:ProgramData -ChildPath $ScriptName
$LogFile = Join-Path -Path $LogFolder -ChildPath "Detection.log"

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
Write-Log -Message "STEP 4: Checking HighConfidenceOptOut Registry Value" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop
    $highConfidenceOptOut = $regValue.HighConfidenceOptOut
    Write-Log -Message "HighConfidenceOptOut value found: $highConfidenceOptOut" -Level INFO
} catch {
    # HighConfidenceOptOut is optional - not present on most systems
    $highConfidenceOptOut = $null
    Write-Log -Message "HighConfidenceOptOut not set (this is normal for most systems)" -Level INFO
}
Write-Log -Message "Result: High Confidence Opt Out = $highConfidenceOptOut" -Level INFO
Write-Log -Message ""

# 4b. MicrosoftUpdateManagedOptIn
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 4b: Checking MicrosoftUpdateManagedOptIn Registry Value" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name MicrosoftUpdateManagedOptIn -ErrorAction Stop
    $microsoftUpdateManagedOptIn = $regValue.MicrosoftUpdateManagedOptIn
    Write-Log -Message "MicrosoftUpdateManagedOptIn value found: $microsoftUpdateManagedOptIn" -Level INFO
} catch {
    # MicrosoftUpdateManagedOptIn is optional - not present on most systems
    $microsoftUpdateManagedOptIn = $null
    Write-Log -Message "MicrosoftUpdateManagedOptIn not set (this is normal for most systems)" -Level INFO
}
Write-Log -Message "Result: Microsoft Update Managed Opt In = $microsoftUpdateManagedOptIn" -Level INFO
Write-Log -Message ""

# 5. AvailableUpdates
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 5: Checking AvailableUpdates Registry Value" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop
    $availableUpdates = $regValue.AvailableUpdates
    if ($null -ne $availableUpdates) {
        # Convert to hexadecimal format
        $availableUpdatesHex = "0x{0:X}" -f $availableUpdates
        Write-Log -Message "AvailableUpdates value found: $availableUpdatesHex" -Level INFO
    } else {
        Write-Log -Message "AvailableUpdates value is null" -Level INFO
    }
} catch {
    Write-Log -Message "AvailableUpdates registry key not found or inaccessible" -Level WARNING
    $availableUpdates = $null
}
Write-Log -Message "Result: Available Updates = $(if ($null -ne $availableUpdates) { $availableUpdatesHex } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 5b. AvailableUpdatesPolicy (GPO-controlled persistent value)
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 5b: Checking AvailableUpdatesPolicy Registry Value" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdatesPolicy -ErrorAction Stop
    $availableUpdatesPolicy = $regValue.AvailableUpdatesPolicy
    if ($null -ne $availableUpdatesPolicy) {
        # Convert to hexadecimal format
        $availableUpdatesPolicyHex = "0x{0:X}" -f $availableUpdatesPolicy
        Write-Log -Message "AvailableUpdatesPolicy value found: $availableUpdatesPolicyHex" -Level INFO
    } else {
        Write-Log -Message "AvailableUpdatesPolicy value is null" -Level INFO
    }
} catch {
    # AvailableUpdatesPolicy is optional - only set when GPO is applied
    $availableUpdatesPolicy = $null
    Write-Log -Message "AvailableUpdatesPolicy not set (only present when GPO is applied)" -Level INFO
}
Write-Log -Message "Result: Available Updates Policy = $(if ($null -ne $availableUpdatesPolicy) { $availableUpdatesPolicyHex } else { 'Not Set' })" -Level INFO
Write-Log -Message ""

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
Write-Log -Message "STEP 7: Checking for UEFI CA 2023 Errors" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop
    $uefica2023Error = $regValue.UEFICA2023Error
    Write-Log -Message "UEFI CA 2023 Error value found: $uefica2023Error" -Level ERROR
} catch {
    # UEFICA2023Error only exists if there was an error - absence is good
    $uefica2023Error = $null
    Write-Log -Message "No UEFI CA 2023 errors recorded (this is good)" -Level SUCCESS
}
Write-Log -Message "Result: UEFI CA 2023 Error = $(if ($null -ne $uefica2023Error) { $uefica2023Error } else { 'None' })" -Level INFO
Write-Log -Message ""

# 9. UEFICA2023ErrorEvent
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 9: Checking for UEFI CA 2023 Error Events" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop
    $uefica2023ErrorEvent = $regValue.UEFICA2023ErrorEvent
    Write-Log -Message "UEFI CA 2023 Error Event found: $uefica2023ErrorEvent" -Level WARNING
} catch {
    $uefica2023ErrorEvent = $null
    Write-Log -Message "No UEFI CA 2023 error events recorded" -Level INFO
}
Write-Log -Message "Result: UEFI CA 2023 Error Event = $(if ($null -ne $uefica2023ErrorEvent) { $uefica2023ErrorEvent } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# Registry: Device Attributes (7 values)
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "DEVICE ATTRIBUTES COLLECTION" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# 10. OEMManufacturerName
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 10: Collecting OEM Manufacturer Name" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop
    $oemManufacturerName = $regValue.OEMManufacturerName
    if ([string]::IsNullOrEmpty($oemManufacturerName)) {
        Write-Log -Message "OEMManufacturerName is empty" -Level WARNING
        $oemManufacturerName = "Unknown"
    } else {
        Write-Log -Message "OEM Manufacturer: $oemManufacturerName" -Level SUCCESS
    }
} catch {
    Write-Log -Message "OEMManufacturerName registry key not found or inaccessible" -Level WARNING
    $oemManufacturerName = $null
}
Write-Log -Message "Result: OEM Manufacturer Name = $(if ($null -ne $oemManufacturerName) { $oemManufacturerName } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 10. OEMModelSystemFamily
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 10b: Collecting OEM Model System Family" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelSystemFamily -ErrorAction Stop
    $oemModelSystemFamily = $regValue.OEMModelSystemFamily
    if ([string]::IsNullOrEmpty($oemModelSystemFamily)) {
        Write-Log -Message "OEMModelSystemFamily is empty" -Level WARNING
        $oemModelSystemFamily = "Unknown"
    } else {
        Write-Log -Message "OEM Model System Family: $oemModelSystemFamily" -Level SUCCESS
    }
} catch {
    Write-Log -Message "OEMModelSystemFamily registry key not found or inaccessible" -Level WARNING
    $oemModelSystemFamily = $null
}
Write-Log -Message "Result: OEM Model System Family = $(if ($null -ne $oemModelSystemFamily) { $oemModelSystemFamily } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 11. OEMModelNumber
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 11: Collecting OEM Model Number" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelNumber -ErrorAction Stop
    $oemModelNumber = $regValue.OEMModelNumber
    if ([string]::IsNullOrEmpty($oemModelNumber)) {
        Write-Log -Message "OEMModelNumber is empty" -Level WARNING
        $oemModelNumber = "Unknown"
    } else {
        Write-Log -Message "OEM Model Number: $oemModelNumber" -Level SUCCESS
    }
} catch {
    Write-Log -Message "OEMModelNumber registry key not found or inaccessible" -Level WARNING
    $oemModelNumber = $null
}
Write-Log -Message "Result: OEM Model Number = $(if ($null -ne $oemModelNumber) { $oemModelNumber } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 12. FirmwareVersion
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 12: Collecting Firmware Version" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareVersion -ErrorAction Stop
    $firmwareVersion = $regValue.FirmwareVersion
    if ([string]::IsNullOrEmpty($firmwareVersion)) {
        Write-Log -Message "FirmwareVersion is empty" -Level WARNING
        $firmwareVersion = "Unknown"
    } else {
        Write-Log -Message "Firmware Version: $firmwareVersion" -Level SUCCESS
    }
} catch {
    Write-Log -Message "FirmwareVersion registry key not found or inaccessible" -Level WARNING
    $firmwareVersion = $null
}
Write-Log -Message "Result: Firmware Version = $(if ($null -ne $firmwareVersion) { $firmwareVersion } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 13. FirmwareReleaseDate
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 13: Collecting Firmware Release Date" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareReleaseDate -ErrorAction Stop
    $firmwareReleaseDate = $regValue.FirmwareReleaseDate
    if ([string]::IsNullOrEmpty($firmwareReleaseDate)) {
        Write-Log -Message "FirmwareReleaseDate is empty" -Level WARNING
        $firmwareReleaseDate = "Unknown"
    } else {
        Write-Log -Message "Firmware Release Date: $firmwareReleaseDate" -Level SUCCESS
    }
} catch {
    Write-Log -Message "FirmwareReleaseDate registry key not found or inaccessible" -Level WARNING
    $firmwareReleaseDate = $null
}
Write-Log -Message "Result: Firmware Release Date = $(if ($null -ne $firmwareReleaseDate) { $firmwareReleaseDate } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 14. OSArchitecture
# PS Version: All | Admin: No | System Requirements: None
Write-Log -Message "STEP 14: Collecting OS Architecture" -Level SECTION
try {
    $osArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        Write-Log -Message "PROCESSOR_ARCHITECTURE env var is empty, trying registry fallback..." -Level INFO
        # Try registry fallback
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OSArchitecture -ErrorAction Stop
        $osArchitecture = $regValue.OSArchitecture
    }
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        Write-Log -Message "OSArchitecture could not be determined" -Level WARNING
        $osArchitecture = "Unknown"
    } else {
        Write-Log -Message "OS Architecture: $osArchitecture" -Level SUCCESS
    }
} catch {
    Write-Log -Message "Error retrieving OSArchitecture: $_" -Level WARNING
    $osArchitecture = "Unknown"
}
Write-Log -Message "Result: OS Architecture = $osArchitecture" -Level INFO
Write-Log -Message ""

# 15. CanAttemptUpdateAfter (FILETIME)
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 15: Checking CanAttemptUpdateAfter" -Level SECTION
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name CanAttemptUpdateAfter -ErrorAction Stop
    $canAttemptUpdateAfter = $regValue.CanAttemptUpdateAfter
    # Convert FILETIME to UTC DateTime - registry stores as REG_BINARY (byte[]) or REG_QWORD (long)
    if ($null -ne $canAttemptUpdateAfter) {
        try {
            if ($canAttemptUpdateAfter -is [byte[]]) {
                $fileTime = [BitConverter]::ToInt64($canAttemptUpdateAfter, 0)
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($fileTime).ToUniversalTime()
            } elseif ($canAttemptUpdateAfter -is [long]) {
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($canAttemptUpdateAfter).ToUniversalTime()
            }
            Write-Log -Message "Can Attempt Update After: $canAttemptUpdateAfter" -Level SUCCESS
        } catch {
            Write-Log -Message "Could not convert CanAttemptUpdateAfter FILETIME to DateTime" -Level WARNING
        }
    }
} catch {
    Write-Log -Message "CanAttemptUpdateAfter registry key not found or inaccessible" -Level WARNING
    $canAttemptUpdateAfter = $null
}
Write-Log -Message "Result: Can Attempt Update After = $(if ($null -ne $canAttemptUpdateAfter) { $canAttemptUpdateAfter } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# Event Logs: System Log (5 values)
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "EVENT LOG ANALYSIS" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# 16-20. Event Log queries
# PS Version: 3.0+ | Admin: May be required for System log | System Requirements: None
Write-Log -Message "STEP 16-20: Querying Secure Boot Event Logs (1801/1808)" -Level SECTION
try {
    $allEventIds = @(1801, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 20 -ErrorAction Stop)

    if ($events.Count -eq 0) {
        Write-Log -Message "No Secure Boot events (1801/1808) found in System log" -Level WARNING
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $event1801Count = 0
        $event1808Count = 0
    } else {
        Write-Log -Message "Found $($events.Count) Secure Boot events" -Level SUCCESS
        
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            Write-Log -Message "Could not determine latest event" -Level WARNING
            $latestEventId = $null
        } else {
            $latestEventId = $latestEvent.Id
            Write-Log -Message "Latest Event ID: $latestEventId (Time: $($latestEvent.TimeCreated))" -Level INFO
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
                Write-Log -Message "Bucket ID: $bucketId" -Level INFO
            } else {
                Write-Log -Message "BucketId not found in event message" -Level WARNING
                $bucketId = $null
            }
        } else {
            Write-Log -Message "Latest event or message is null, cannot extract BucketId" -Level WARNING
            $bucketId = $null
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
                Write-Log -Message "Confidence: $confidence" -Level INFO
            } else {
                Write-Log -Message "Confidence level not found in event message" -Level WARNING
                $confidence = $null
            }
        } else {
            Write-Log -Message "Latest event or message is null, cannot extract Confidence" -Level WARNING
            $confidence = $null
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count
        Write-Log -Message "Event 1801 Count: $event1801Count" -Level INFO

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        if ($event1808Count -gt 0) {
            Write-Log -Message "Event 1808 Count: $event1808Count (errors detected)" -Level WARNING
        } else {
            Write-Log -Message "Event 1808 Count: $event1808Count" -Level INFO
        }
    }
} catch {
    Write-Log -Message "Error retrieving event logs. May require administrator privileges: $_" -Level ERROR
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $event1801Count = 0
    $event1808Count = 0
}
Write-Log -Message ""

# WMI/CIM Queries (4 values)
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "SYSTEM INFORMATION COLLECTION" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# 21. OSVersion
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
Write-Log -Message "STEP 21: Collecting OS Version" -Level SECTION
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or [string]::IsNullOrEmpty($osInfo.Version)) {
        Write-Log -Message "Could not retrieve OS version via CIM" -Level WARNING
        $osVersion = "Unknown"
    } else {
        $osVersion = $osInfo.Version
        Write-Log -Message "OS Version: $osVersion" -Level SUCCESS
    }
} catch {
    # CIM may fail in some environments - use fallback
    Write-Log -Message "CIM query failed, using .NET fallback" -Level WARNING
    $osVersion = [System.Environment]::OSVersion.Version.ToString()
    if ([string]::IsNullOrEmpty($osVersion)) { $osVersion = "Unknown" }
    Write-Log -Message "OS Version (fallback): $osVersion" -Level INFO
}
Write-Log -Message "Result: OS Version = $osVersion" -Level INFO
Write-Log -Message ""

# 22. LastBootTime
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
Write-Log -Message "STEP 22: Collecting Last Boot Time" -Level SECTION
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or $null -eq $osInfo.LastBootUpTime) {
        Write-Log -Message "Could not retrieve last boot time" -Level WARNING
        $lastBootTime = $null
    } else {
        $lastBootTime = $osInfo.LastBootUpTime
        Write-Log -Message "Last Boot Time: $lastBootTime" -Level SUCCESS
    }
} catch {
    # CIM may fail in some environments - use fallback
    Write-Log -Message "CIM query failed, attempting fallback" -Level WARNING
    try {
        $lastBootTime = (Get-Process -Id 0 -ErrorAction SilentlyContinue).StartTime
    } catch {
        $lastBootTime = $null
    }
    if ($lastBootTime) { 
        Write-Log -Message "Last Boot Time (fallback): $lastBootTime" -Level INFO 
    } else { 
        Write-Log -Message "Last Boot Time: Not Available" -Level WARNING 
    }
}
Write-Log -Message "Result: Last Boot Time = $(if ($null -ne $lastBootTime) { $lastBootTime } else { 'Not Available' })" -Level INFO
Write-Log -Message ""

# 23. BaseBoardManufacturer
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
Write-Log -Message "STEP 23: Collecting Baseboard Manufacturer" -Level SECTION
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Manufacturer)) {
        Write-Log -Message "Could not retrieve baseboard manufacturer" -Level WARNING
        $baseBoardManufacturer = "Unknown"
    } else {
        $baseBoardManufacturer = $baseBoard.Manufacturer
        Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer" -Level SUCCESS
    }
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardManufacturer = "Unknown"
    Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer (CIM query failed)" -Level WARNING
}
Write-Log -Message "Result: Baseboard Manufacturer = $baseBoardManufacturer" -Level INFO
Write-Log -Message ""

# 24. BaseBoardProduct
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
Write-Log -Message "STEP 24: Collecting Baseboard Product" -Level SECTION
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Product)) {
        Write-Log -Message "Could not retrieve baseboard product" -Level WARNING
        $baseBoardProduct = "Unknown"
    } else {
        $baseBoardProduct = $baseBoard.Product
        Write-Log -Message "Baseboard Product: $baseBoardProduct" -Level SUCCESS
    }
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardProduct = "Unknown"
    Write-Log -Message "Baseboard Product: $baseBoardProduct (CIM query failed)" -Level WARNING
}
Write-Log -Message "Result: Baseboard Product = $baseBoardProduct" -Level INFO
Write-Log -Message ""

# 25. SecureBootTaskEnabled
# PS Version: All | Admin: No | System Requirements: Scheduled Task exists
# Checks if the Secure-Boot-Update scheduled task is enabled
Write-Log -Message "STEP 25: Checking Secure Boot Update Scheduled Task" -Level SECTION
$secureBootTaskEnabled = $null
$secureBootTaskStatus = "Unknown"
try {
    $taskOutput = schtasks.exe /Query /TN "\Microsoft\Windows\PI\Secure-Boot-Update" /FO CSV 2>&1
    if ($LASTEXITCODE -eq 0) {
        $taskData = $taskOutput | ConvertFrom-Csv
        if ($taskData) {
            $secureBootTaskStatus = $taskData.Status
            $secureBootTaskEnabled = ($taskData.Status -eq 'Ready' -or $taskData.Status -eq 'Running')
        }
    } else {
        $secureBootTaskStatus = "NotFound"
        $secureBootTaskEnabled = $false
    }
    if ($secureBootTaskEnabled -eq $false) {
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -Level WARNING
    } else {
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -Level SUCCESS
    }
} catch {
    $secureBootTaskStatus = "Error"
    $secureBootTaskEnabled = $false
    Write-Log -Message "SecureBoot Update Task: Error checking - $_" -Level ERROR
}
Write-Log -Message "Result: Secure Boot Task Enabled = $secureBootTaskEnabled" -Level INFO
Write-Log -Message ""

# =============================================================================
# Remediation Detection - Status Output & Exit Code
# =============================================================================
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "FINAL STATUS SUMMARY" -Level SECTION
Write-Log -Message "========================================" -Level SECTION

# Build status object from all collected inventory data
$status = [ordered]@{
    UEFICA2023Status           = $uefica2023Status
    UEFICA2023Error            = $uefica2023Error
    UEFICA2023ErrorEvent       = $uefica2023ErrorEvent
    AvailableUpdates           = if ($null -ne $availableUpdates) { $availableUpdatesHex } else { $null }
    AvailableUpdatesPolicy     = if ($null -ne $availableUpdatesPolicy) { $availableUpdatesPolicyHex } else { $null }
    Hostname                   = $hostname
    CollectionTime             = if ($collectionTime -is [datetime]) { $collectionTime.ToString("o") } else { "$collectionTime" }
    SecureBootEnabled          = $secureBootEnabled
    HighConfidenceOptOut       = $highConfidenceOptOut
    MicrosoftUpdateManagedOptIn        = $microsoftUpdateManagedOptIn
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
    SecureBootTaskEnabled      = $secureBootTaskEnabled
    SecureBootTaskStatus       = $secureBootTaskStatus
}

# Output the status - For data aggregation
$jsonOutput = $status | ConvertTo-Json -Compress
Write-Log -Message "JSON output generated successfully" -Level INFO

# If OutputPath provided, save to file; otherwise output to stdout
if (-not [string]::IsNullOrEmpty($OutputPath)) {
    # Validate OutputPath - skip if it looks like a help request or has invalid chars
    if ($OutputPath -match '^[/\-]' -or $OutputPath -match '[<>:"|?*]') {
        Write-Log -Message "Invalid OutputPath specified, outputting to stdout" -Level WARNING
        Write-Output $jsonOutput
        Write-Log -Message "========================================" -Level SECTION
        Write-Log -Message "Script completed. Log file: $LogFile" -Level SECTION
        Write-Log -Message "========================================" -Level SECTION
        if ($secureBootEnabled -and $uefica2023Status -eq "Updated") { exit 0 } else { exit 1 }
    }
    
    # Ensure the output folder exists
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Log -Message "Created output folder: $OutputPath" -Level INFO
        } catch {
            Write-Log -Message "Could not create output folder: $OutputPath - $_" -Level WARNING
        }
    }
    
    # Save to HOSTNAME_latest.json
    $outputFile = Join-Path $OutputPath "$($hostname)_latest.json"
    try {
        $jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8 -Force
        Write-Log -Message "JSON saved to: $outputFile" -Level SUCCESS
    } catch {
        Write-Log -Message "Could not write to file: $outputFile - $_" -Level WARNING
        # Fall back to stdout
        Write-Output $jsonOutput
    }
} else {
    # Original behavior - output to stdout
    Write-Output $jsonOutput
}

# Final summary
Write-Log -Message "" -Level INFO
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "SCRIPT EXECUTION COMPLETE" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "Log file saved to: $LogFile" -Level INFO
if ($secureBootEnabled -and $uefica2023Status -eq "Updated") {
    Write-Log -Message "RESULT: Device is COMPLIANT - Secure Boot enabled and certificates updated" -Level SUCCESS
    Write-Log -Message "Exit Code: 0 (Without issue)" -Level SUCCESS
} else {
    Write-Log -Message "RESULT: Device requires attention - Review status above" -Level WARNING
    Write-Log -Message "Exit Code: 1 (With issue)" -Level WARNING
}

# Exit code: "Updated" is the success value per the playbook
if ($secureBootEnabled -and $uefica2023Status -eq "Updated") {
    exit 0  # Without issue
} else {
    exit 1  # With issue
}
