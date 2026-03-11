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

# Create log folder and file
$ScriptName = "PAM - Secure Boot - Cert Update Status Detection"
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

# Logging function - writes to both console and log file
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO','SUCCESS','WARNING','ERROR')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"

    # Write to log file
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if log file is inaccessible
    }
}

# Initialize log file
Write-Log -Message "========================================"
Write-Log -Message "Secure Boot Certificate Detection Script"
Write-Log -Message "Started: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')"
Write-Log -Message "Log File: $LogFile"
Write-Log -Message "========================================"

# Download URL: https://aka.ms/getsecureboot -> "Deployment and Monitoring Samples"
# Note: This script runs on endpoints to collect Secure Boot status data.

# 1. HostName
# PS Version: All | Admin: No | System Requirements: None
Write-Log -Message "STEP 1: Collecting Device Hostname"
try {
    $hostname = $env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($hostname)) {
        Write-Warning "Hostname could not be determined"
        Write-Log -Message "Hostname could not be determined" -Level WARNING
        $hostname = "Unknown"
    }
    Write-Host "Hostname: $hostname"
    Write-Log -Message "Hostname: $hostname" -Level SUCCESS
} catch {
    Write-Warning "Error retrieving hostname: $_"
    Write-Log -Message "Error retrieving hostname: $_" -Level ERROR
    $hostname = "Error"
    Write-Host "Hostname: $hostname"
    Write-Log -Message "Hostname: $hostname"
}

# 2. CollectionTime
# PS Version: All | Admin: No | System Requirements: None
Write-Log -Message "STEP 2: Recording Collection Timestamp"
try {
    $collectionTime = Get-Date
    if ($null -eq $collectionTime) {
        Write-Warning "Could not retrieve current date/time"
        Write-Log -Message "Could not retrieve current date/time" -Level WARNING
        $collectionTime = "Unknown"
    }
    Write-Host "Collection Time: $collectionTime"
    Write-Log -Message "Collection Time: $collectionTime" -Level SUCCESS
} catch {
    Write-Warning "Error retrieving date/time: $_"
    Write-Log -Message "Error retrieving date/time: $_" -Level ERROR
    $collectionTime = "Error"
    Write-Host "Collection Time: $collectionTime"
    Write-Log -Message "Collection Time: $collectionTime"
}

# Registry: Secure Boot Main Key (3 values)
Write-Log -Message "========================================"
Write-Log -Message "SECURE BOOT STATUS DETECTION"
Write-Log -Message "========================================"

# 3. SecureBootEnabled
# PS Version: 3.0+ | Admin: May be required | System Requirements: UEFI/Secure Boot capable system
Write-Log -Message "STEP 3: Checking if Secure Boot is Enabled"
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    Write-Host "Secure Boot Enabled: $secureBootEnabled"
    Write-Log -Message "Secure Boot Enabled: $secureBootEnabled" -Level SUCCESS
} catch {
    Write-Warning "Unable to determine Secure Boot status via cmdlet: $_"
    Write-Log -Message "Unable to determine Secure Boot status via cmdlet: $_" -Level WARNING
    # Try registry fallback
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
        $secureBootEnabled = [bool]$regValue.UEFISecureBootEnabled
        Write-Host "Secure Boot Enabled: $secureBootEnabled"
        Write-Log -Message "Secure Boot Enabled: $secureBootEnabled (via registry)" -Level SUCCESS
    } catch {
        Write-Warning "Unable to determine Secure Boot status via registry. System may not support UEFI/Secure Boot."
        Write-Log -Message "Unable to determine Secure Boot status. System may not support UEFI/Secure Boot." -Level ERROR
        $secureBootEnabled = $null
        Write-Host "Secure Boot Enabled: Not Available"
        Write-Log -Message "Secure Boot Enabled: Not Available"
    }
}

# 4. HighConfidenceOptOut
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 4: Checking HighConfidenceOptOut Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop
    $highConfidenceOptOut = $regValue.HighConfidenceOptOut
    Write-Host "High Confidence Opt Out: $highConfidenceOptOut"
    Write-Log -Message "High Confidence Opt Out: $highConfidenceOptOut"
} catch {
    # HighConfidenceOptOut is optional - not present on most systems
    $highConfidenceOptOut = $null
    Write-Host "High Confidence Opt Out: Not Set"
    Write-Log -Message "High Confidence Opt Out: Not Set (normal for most systems)"
}

# 4b. MicrosoftUpdateManagedOptIn
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 4b: Checking MicrosoftUpdateManagedOptIn Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name MicrosoftUpdateManagedOptIn -ErrorAction Stop
    $microsoftUpdateManagedOptIn = $regValue.MicrosoftUpdateManagedOptIn
    Write-Host "Microsoft Update Managed Opt In: $microsoftUpdateManagedOptIn"
    Write-Log -Message "Microsoft Update Managed Opt In: $microsoftUpdateManagedOptIn"
} catch {
    # MicrosoftUpdateManagedOptIn is optional - not present on most systems
    $microsoftUpdateManagedOptIn = $null
    Write-Host "Microsoft Update Managed Opt In: Not Set"
    Write-Log -Message "Microsoft Update Managed Opt In: Not Set (normal for most systems)"
}

# 5. AvailableUpdates
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 5: Checking AvailableUpdates Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop
    $availableUpdates = $regValue.AvailableUpdates
    if ($null -ne $availableUpdates) {
        # Convert to hexadecimal format
        $availableUpdatesHex = "0x{0:X}" -f $availableUpdates
        Write-Host "Available Updates: $availableUpdatesHex"
        Write-Log -Message "Available Updates: $availableUpdatesHex"
    } else {
        Write-Host "Available Updates: Not Available"
        Write-Log -Message "Available Updates: Not Available"
    }
} catch {
    Write-Warning "AvailableUpdates registry key not found or inaccessible"
    Write-Log -Message "AvailableUpdates registry key not found or inaccessible" -Level WARNING
    $availableUpdates = $null
    Write-Host "Available Updates: Not Available"
    Write-Log -Message "Available Updates: Not Available"
}

# 5b. AvailableUpdatesPolicy (GPO-controlled persistent value)
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 5b: Checking AvailableUpdatesPolicy Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdatesPolicy -ErrorAction Stop
    $availableUpdatesPolicy = $regValue.AvailableUpdatesPolicy
    if ($null -ne $availableUpdatesPolicy) {
        # Convert to hexadecimal format
        $availableUpdatesPolicyHex = "0x{0:X}" -f $availableUpdatesPolicy
        Write-Host "Available Updates Policy: $availableUpdatesPolicyHex"
        Write-Log -Message "Available Updates Policy: $availableUpdatesPolicyHex"
    } else {
        Write-Host "Available Updates Policy: Not Set"
        Write-Log -Message "Available Updates Policy: Not Set"
    }
} catch {
    # AvailableUpdatesPolicy is optional - only set when GPO is applied
    $availableUpdatesPolicy = $null
    Write-Host "Available Updates Policy: Not Set"
    Write-Log -Message "Available Updates Policy: Not Set (only set when GPO is applied)"
}

# Registry: Servicing Key (3 values)
Write-Log -Message "========================================"
Write-Log -Message "SERVICING REGISTRY KEYS"
Write-Log -Message "========================================"

# 6. UEFICA2023Status
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 6: Checking UEFICA2023Status Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop
    $uefica2023Status = $regValue.UEFICA2023Status
    Write-Host "Windows UEFI CA 2023 Status: $uefica2023Status"
    Write-Log -Message "Windows UEFI CA 2023 Status: $uefica2023Status" -Level SUCCESS
} catch {
    Write-Warning "Windows UEFI CA 2023 Status registry key not found or inaccessible"
    Write-Log -Message "Windows UEFI CA 2023 Status registry key not found or inaccessible" -Level WARNING
    $uefica2023Status = $null
    Write-Host "Windows UEFI CA 2023 Status: Not Available"
    Write-Log -Message "Windows UEFI CA 2023 Status: Not Available"
}

# 7. UEFICA2023Error
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 7: Checking UEFICA2023Error Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop
    $uefica2023Error = $regValue.UEFICA2023Error
    Write-Host "UEFI CA 2023 Error: $uefica2023Error"
    Write-Log -Message "UEFI CA 2023 Error: $uefica2023Error" -Level WARNING
} catch {
    # UEFICA2023Error only exists if there was an error - absence is good
    $uefica2023Error = $null
    Write-Host "UEFI CA 2023 Error: None"
    Write-Log -Message "UEFI CA 2023 Error: None (absence is good)"
}

# 8. UEFICA2023ErrorEvent
# PS Version: All | Admin: May be required | System Requirements: None
Write-Log -Message "STEP 8: Checking UEFICA2023ErrorEvent Registry Value"
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop
    $uefica2023ErrorEvent = $regValue.UEFICA2023ErrorEvent
    Write-Host "UEFI CA 2023 Error Event: $uefica2023ErrorEvent"
    Write-Log -Message "UEFI CA 2023 Error Event: $uefica2023ErrorEvent" -Level WARNING
} catch {
    $uefica2023ErrorEvent = $null
    Write-Host "UEFI CA 2023 Error Event: Not Available"
    Write-Log -Message "UEFI CA 2023 Error Event: Not Available"
}

# Registry: Device Attributes (7 values: 9-15)
Write-Log -Message "========================================"
Write-Log -Message "DEVICE ATTRIBUTES"
Write-Log -Message "========================================"

# 9. OEMManufacturerName
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop
    $oemManufacturerName = $regValue.OEMManufacturerName
    if ([string]::IsNullOrEmpty($oemManufacturerName)) {
        Write-Warning "OEMManufacturerName is empty"
        $oemManufacturerName = "Unknown"
    }
    Write-Host "OEM Manufacturer Name: $oemManufacturerName"
    Write-Log -Message "OEM Manufacturer Name: $oemManufacturerName"
} catch {
    Write-Warning "OEMManufacturerName registry key not found or inaccessible"
    Write-Log -Message "OEMManufacturerName registry key not found" -Level WARNING
    $oemManufacturerName = $null
    Write-Host "OEM Manufacturer Name: Not Available"
    Write-Log -Message "OEM Manufacturer Name: Not Available"
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
    Write-Log -Message "OEM Model System Family: $oemModelSystemFamily"
} catch {
    Write-Warning "OEMModelSystemFamily registry key not found or inaccessible"
    Write-Log -Message "OEMModelSystemFamily registry key not found" -Level WARNING
    $oemModelSystemFamily = $null
    Write-Host "OEM Model System Family: Not Available"
    Write-Log -Message "OEM Model System Family: Not Available"
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
    Write-Log -Message "OEM Model Number: $oemModelNumber"
} catch {
    Write-Warning "OEMModelNumber registry key not found or inaccessible"
    Write-Log -Message "OEMModelNumber registry key not found" -Level WARNING
    $oemModelNumber = $null
    Write-Host "OEM Model Number: Not Available"
    Write-Log -Message "OEM Model Number: Not Available"
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
    Write-Log -Message "Firmware Version: $firmwareVersion"
} catch {
    Write-Warning "FirmwareVersion registry key not found or inaccessible"
    Write-Log -Message "FirmwareVersion registry key not found" -Level WARNING
    $firmwareVersion = $null
    Write-Host "Firmware Version: Not Available"
    Write-Log -Message "Firmware Version: Not Available"
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
    Write-Log -Message "Firmware Release Date: $firmwareReleaseDate"
} catch {
    Write-Warning "FirmwareReleaseDate registry key not found or inaccessible"
    Write-Log -Message "FirmwareReleaseDate registry key not found" -Level WARNING
    $firmwareReleaseDate = $null
    Write-Host "Firmware Release Date: Not Available"
    Write-Log -Message "Firmware Release Date: Not Available"
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
    Write-Log -Message "OS Architecture: $osArchitecture"
} catch {
    Write-Warning "Error retrieving OSArchitecture: $_"
    Write-Log -Message "Error retrieving OSArchitecture: $_" -Level WARNING
    $osArchitecture = "Unknown"
    Write-Host "OS Architecture: $osArchitecture"
    Write-Log -Message "OS Architecture: $osArchitecture"
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
            Write-Log -Message "Could not convert CanAttemptUpdateAfter FILETIME to DateTime" -Level WARNING
        }
    }
    Write-Host "Can Attempt Update After: $canAttemptUpdateAfter"
    Write-Log -Message "Can Attempt Update After: $canAttemptUpdateAfter"
} catch {
    Write-Warning "CanAttemptUpdateAfter registry key not found or inaccessible"
    Write-Log -Message "CanAttemptUpdateAfter registry key not found" -Level WARNING
    $canAttemptUpdateAfter = $null
    Write-Host "Can Attempt Update After: Not Available"
    Write-Log -Message "Can Attempt Update After: Not Available"
}

# Event Logs: System Log (10 values: 16-25)
Write-Log -Message "========================================"
Write-Log -Message "EVENT LOG ANALYSIS"
Write-Log -Message "========================================"

# 16-25. Event Log queries
# Event IDs:
#   1801 - Update initiated, reboot required
#   1808 - Update completed successfully
#   1795 - Firmware returned error (capture error code)
#   1796 - Error logged with error code (capture code)
#   1800 - Reboot needed (NOT an error - update will proceed after reboot)
#   1802 - Known firmware issue blocked update (capture KI_<number> from SkipReason)
#   1803 - Matching KEK update not found (OEM needs to supply PK signed KEK)
# PS Version: 3.0+ | Admin: May be required for System log | System Requirements: None
try {
    # Query all relevant Secure Boot event IDs
    $allEventIds = @(1795, 1796, 1800, 1801, 1802, 1803, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 50 -ErrorAction Stop)

    if ($events.Count -eq 0) {
        Write-Warning "No Secure Boot events found in System log"
        Write-Log -Message "No Secure Boot events found in System log" -Level WARNING
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $skipReasonKnownIssue = $null
        $event1801Count = 0
        $event1808Count = 0
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        Write-Host "Latest Event ID: Not Available"
        Write-Log -Message "Latest Event ID: Not Available"
        Write-Host "Bucket ID: Not Available"
        Write-Log -Message "Bucket ID: Not Available"
        Write-Host "Confidence: Not Available"
        Write-Log -Message "Confidence: Not Available"
        Write-Host "Event 1801 Count: 0"
        Write-Log -Message "Event 1801 Count: 0"
        Write-Host "Event 1808 Count: 0"
        Write-Log -Message "Event 1808 Count: 0"
    } else {
        Write-Log -Message "Found $($events.Count) Secure Boot events in System log"
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            Write-Warning "Could not determine latest event"
            Write-Log -Message "Could not determine latest event" -Level WARNING
            $latestEventId = $null
            Write-Host "Latest Event ID: Not Available"
            Write-Log -Message "Latest Event ID: Not Available"
        } else {
            $latestEventId = $latestEvent.Id
            Write-Host "Latest Event ID: $latestEventId"
            Write-Log -Message "Latest Event ID: $latestEventId"
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
                Write-Host "Bucket ID: $bucketId"
                Write-Log -Message "Bucket ID: $bucketId"
            } else {
                Write-Warning "BucketId not found in event message"
                Write-Log -Message "BucketId not found in event message" -Level WARNING
                $bucketId = $null
                Write-Host "Bucket ID: Not Found in Event"
                Write-Log -Message "Bucket ID: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract BucketId"
            Write-Log -Message "Latest event or message is null" -Level WARNING
            $bucketId = $null
            Write-Host "Bucket ID: Not Available"
            Write-Log -Message "Bucket ID: Not Available"
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
                Write-Host "Confidence: $confidence"
                Write-Log -Message "Confidence: $confidence"
            } else {
                Write-Warning "Confidence level not found in event message"
                Write-Log -Message "Confidence level not found in event message" -Level WARNING
                $confidence = $null
                Write-Host "Confidence: Not Found in Event"
                Write-Log -Message "Confidence: Not Found in Event"
            }
        } else {
            Write-Warning "Latest event or message is null, cannot extract Confidence"
            Write-Log -Message "Latest event or message is null" -Level WARNING
            $confidence = $null
            Write-Host "Confidence: Not Available"
            Write-Log -Message "Confidence: Not Available"
        }

        # 18b. SkipReason - Extract KI_<number> from SkipReason in the same event as BucketId
        # This captures Known Issue IDs that appear alongside BucketId/Confidence (not just Event 1802)
        $skipReasonKnownIssue = $null
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'SkipReason:\s*(KI_\d+)') {
                $skipReasonKnownIssue = $matches[1]
                Write-Host "SkipReason Known Issue: $skipReasonKnownIssue" -ForegroundColor Yellow
                Write-Log -Message "SkipReason Known Issue: $skipReasonKnownIssue" -Level WARNING
            }
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count
        Write-Host "Event 1801 Count: $event1801Count"
        Write-Log -Message "Event 1801 Count: $event1801Count"

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        Write-Host "Event 1808 Count: $event1808Count"
        Write-Log -Message "Event 1808 Count: $event1808Count"
        
        # Initialize error event variables
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        
        # Only check for error events if update is NOT complete
        # Skip error analysis if: 1808 is latest event OR UEFICA2023Status is "Updated"
        $updateComplete = ($latestEventId -eq 1808) -or ($uefica2023Status -eq "Updated")
        
        if (-not $updateComplete) {
            Write-Host "Update not complete - checking for error events..." -ForegroundColor Yellow
            Write-Log -Message "Update not complete - checking for error events..." -Level WARNING
            
            # 21. Event1795 - Firmware Error (capture error code)
            $event1795Array = @($events | Where-Object {$_.Id -eq 1795})
            $event1795Count = $event1795Array.Count
            if ($event1795Count -gt 0) {
                $latestEvent1795 = $event1795Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1795.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1795ErrorCode = $matches[1]
                }
                Write-Host "Event 1795 (Firmware Error) Count: $event1795Count" $(if ($event1795ErrorCode) { "Code: $event1795ErrorCode" })
                Write-Log -Message "Event 1795 (Firmware Error) Count: $event1795Count $(if ($event1795ErrorCode) { "Code: $event1795ErrorCode" })" -Level WARNING
            }
            
            # 22. Event1796 - Error Code Logged (capture error code)
            $event1796Array = @($events | Where-Object {$_.Id -eq 1796})
            $event1796Count = $event1796Array.Count
            if ($event1796Count -gt 0) {
                $latestEvent1796 = $event1796Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1796.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1796ErrorCode = $matches[1]
                }
                Write-Host "Event 1796 (Error Logged) Count: $event1796Count" $(if ($event1796ErrorCode) { "Code: $event1796ErrorCode" })
                Write-Log -Message "Event 1796 (Error Logged) Count: $event1796Count $(if ($event1796ErrorCode) { "Code: $event1796ErrorCode" })" -Level WARNING
            }
            
            # 23. Event1800 - Reboot Needed (NOT an error - update will proceed after reboot)
            $event1800Array = @($events | Where-Object {$_.Id -eq 1800})
            $event1800Count = $event1800Array.Count
            $rebootPending = $event1800Count -gt 0
            if ($rebootPending) {
                Write-Host "Event 1800 (Reboot Pending): Update will proceed after reboot" -ForegroundColor Cyan
                Write-Log -Message "Event 1800 (Reboot Pending): Update will proceed after reboot"
            }
            
            # 24. Event1802 - Known Firmware Issue (capture KI_<number> from SkipReason)
            $event1802Array = @($events | Where-Object {$_.Id -eq 1802})
            $event1802Count = $event1802Array.Count
            if ($event1802Count -gt 0) {
                $latestEvent1802 = $event1802Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                    $knownIssueId = $matches[1]
                }
                Write-Host "Event 1802 (Known Firmware Issue) Count: $event1802Count" $(if ($knownIssueId) { "KI: $knownIssueId" })
                Write-Log -Message "Event 1802 (Known Firmware Issue) Count: $event1802Count $(if ($knownIssueId) { "KI: $knownIssueId" })" -Level WARNING
            }
            
            # 25. Event1803 - Missing KEK Update (OEM needs to supply PK signed KEK)
            $event1803Array = @($events | Where-Object {$_.Id -eq 1803})
            $event1803Count = $event1803Array.Count
            $missingKEK = $event1803Count -gt 0
            if ($missingKEK) {
                Write-Host "Event 1803 (Missing KEK): OEM needs to supply PK signed KEK" -ForegroundColor Yellow
                Write-Log -Message "Event 1803 (Missing KEK): OEM needs to supply PK signed KEK" -Level WARNING
            }
        } else {
            Write-Host "Update complete (Event 1808 or Status=Updated) - skipping error analysis" -ForegroundColor Green
            Write-Log -Message "Update complete (Event 1808 or Status=Updated) - skipping error analysis" -Level SUCCESS
        }
    }
} catch {
    Write-Warning "Error retrieving event logs. May require administrator privileges: $_"
    Write-Log -Message "Error retrieving event logs: $_" -Level ERROR
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $skipReasonKnownIssue = $null
    $event1801Count = 0
    $event1808Count = 0
    $event1795Count = 0
    $event1795ErrorCode = $null
    $event1796Count = 0
    $event1796ErrorCode = $null
    $event1800Count = 0
    $rebootPending = $false
    $event1802Count = 0
    $knownIssueId = $null
    $event1803Count = 0
    $missingKEK = $false
    Write-Host "Latest Event ID: Error"
    Write-Log -Message "Latest Event ID: Error" -Level ERROR
    Write-Host "Bucket ID: Error"
    Write-Log -Message "Bucket ID: Error" -Level ERROR
    Write-Host "Confidence: Error"
    Write-Log -Message "Confidence: Error" -Level ERROR
    Write-Host "Event 1801 Count: 0"
    Write-Log -Message "Event 1801 Count: 0" -Level ERROR
    Write-Host "Event 1808 Count: 0"
    Write-Log -Message "Event 1808 Count: 0" -Level ERROR
}

# WMI/CIM Queries (5 values)
Write-Log -Message "========================================"
Write-Log -Message "WMI/CIM QUERIES"
Write-Log -Message "========================================"

# 26. OSVersion
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or [string]::IsNullOrEmpty($osInfo.Version)) {
        Write-Warning "Could not retrieve OS version"
        Write-Log -Message "Could not retrieve OS version" -Level WARNING
        $osVersion = "Unknown"
    } else {
        $osVersion = $osInfo.Version
    }
    Write-Host "OS Version: $osVersion"
    Write-Log -Message "OS Version: $osVersion"
} catch {
    # CIM may fail in some environments - use fallback
    $osVersion = [System.Environment]::OSVersion.Version.ToString()
    if ([string]::IsNullOrEmpty($osVersion)) { $osVersion = "Unknown" }
    Write-Host "OS Version: $osVersion"
    Write-Log -Message "OS Version: $osVersion (fallback)"
}

# 27. LastBootTime
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or $null -eq $osInfo.LastBootUpTime) {
        Write-Warning "Could not retrieve last boot time"
        Write-Log -Message "Could not retrieve last boot time" -Level WARNING
        $lastBootTime = $null
        Write-Host "Last Boot Time: Not Available"
        Write-Log -Message "Last Boot Time: Not Available"
    } else {
        $lastBootTime = $osInfo.LastBootUpTime
        Write-Host "Last Boot Time: $lastBootTime"
        Write-Log -Message "Last Boot Time: $lastBootTime"
    }
} catch {
    # CIM may fail in some environments - use fallback
    try {
        $lastBootTime = (Get-Process -Id 0 -ErrorAction SilentlyContinue).StartTime
    } catch {
        $lastBootTime = $null
    }
    if ($lastBootTime) { 
        Write-Host "Last Boot Time: $lastBootTime"
        Write-Log -Message "Last Boot Time: $lastBootTime (fallback)"
    } else { 
        Write-Host "Last Boot Time: Not Available"
        Write-Log -Message "Last Boot Time: Not Available"
    }
}

# 28. BaseBoardManufacturer
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Manufacturer)) {
        Write-Warning "Could not retrieve baseboard manufacturer"
        Write-Log -Message "Could not retrieve baseboard manufacturer" -Level WARNING
        $baseBoardManufacturer = "Unknown"
    } else {
        $baseBoardManufacturer = $baseBoard.Manufacturer
    }
    Write-Host "Baseboard Manufacturer: $baseBoardManufacturer"
    Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer"
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardManufacturer = "Unknown"
    Write-Host "Baseboard Manufacturer: $baseBoardManufacturer"
    Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer"
}

# 29. BaseBoardProduct
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Product)) {
        Write-Warning "Could not retrieve baseboard product"
        Write-Log -Message "Could not retrieve baseboard product" -Level WARNING
        $baseBoardProduct = "Unknown"
    } else {
        $baseBoardProduct = $baseBoard.Product
    }
    Write-Host "Baseboard Product: $baseBoardProduct"
    Write-Log -Message "Baseboard Product: $baseBoardProduct"
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardProduct = "Unknown"
    Write-Host "Baseboard Product: $baseBoardProduct"
    Write-Log -Message "Baseboard Product: $baseBoardProduct"
}

# 30. SecureBootTaskEnabled
# PS Version: All | Admin: No | System Requirements: Scheduled Task exists
# Checks if the Secure-Boot-Update scheduled task is enabled
Write-Log -Message "========================================"
Write-Log -Message "SCHEDULED TASK & WINCS STATUS"
Write-Log -Message "========================================"
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
        Write-Host "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -ForegroundColor Yellow
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -Level WARNING
    } else {
        Write-Host "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -ForegroundColor Green
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -Level SUCCESS
    }
} catch {
    $secureBootTaskStatus = "Error"
    $secureBootTaskEnabled = $false
    Write-Host "SecureBoot Update Task: Error checking - $_" -ForegroundColor Red
    Write-Log -Message "SecureBoot Update Task: Error checking - $_" -Level ERROR
}

# 31. WinCS Key Status (F33E0C8E002 - Secure Boot Certificate Update)
# PS Version: All | Admin: Yes (for query) | System Requirements: WinCsFlags.exe
$wincsKeyApplied = $null
$wincsKeyStatus = "Unknown"
try {
    # Check common locations for WinCsFlags.exe
    $wincsFlagsPath = $null
    $possiblePaths = @(
        "$env:SystemRoot\System32\WinCsFlags.exe",
        "$env:SystemRoot\SysWOW64\WinCsFlags.exe"
    )
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) { $wincsFlagsPath = $p; break }
    }
    
    if ($wincsFlagsPath) {
        # Query specific key - requires admin rights
        $queryOutput = & $wincsFlagsPath /query --key F33E0C8E002 2>&1
        $queryOutputStr = $queryOutput -join "`n"
        
        if ($LASTEXITCODE -eq 0) {
            # Check if key is applied (look for "Active Configuration" or similar indicator)
            if ($queryOutputStr -match "Active Configuration.*:.*enabled" -or $queryOutputStr -match "Configuration.*applied") {
                $wincsKeyApplied = $true
                $wincsKeyStatus = "Applied"
                Write-Host "WinCS Key F33E0C8E002: Applied" -ForegroundColor Green
                Write-Log -Message "WinCS Key F33E0C8E002: Applied" -Level SUCCESS
            } elseif ($queryOutputStr -match "not found|No configuration") {
                $wincsKeyApplied = $false
                $wincsKeyStatus = "NotApplied"
                Write-Host "WinCS Key F33E0C8E002: Not Applied" -ForegroundColor Yellow
                Write-Log -Message "WinCS Key F33E0C8E002: Not Applied" -Level WARNING
            } else {
                # Key exists - check output for state
                $wincsKeyApplied = $true
                $wincsKeyStatus = "Applied"
                Write-Host "WinCS Key F33E0C8E002: Applied" -ForegroundColor Green
                Write-Log -Message "WinCS Key F33E0C8E002: Applied" -Level SUCCESS
            }
        } else {
            # Check for specific error messages
            if ($queryOutputStr -match "Access denied|administrator") {
                $wincsKeyStatus = "AccessDenied"
                Write-Host "WinCS Key F33E0C8E002: Access denied (run as admin)" -ForegroundColor DarkGray
                Write-Log -Message "WinCS Key F33E0C8E002: Access denied (run as admin)"
            } elseif ($queryOutputStr -match "not found|No configuration") {
                $wincsKeyApplied = $false
                $wincsKeyStatus = "NotApplied"
                Write-Host "WinCS Key F33E0C8E002: Not Applied" -ForegroundColor Yellow
                Write-Log -Message "WinCS Key F33E0C8E002: Not Applied" -Level WARNING
            } else {
                $wincsKeyStatus = "QueryFailed"
                Write-Host "WinCS Key F33E0C8E002: Query failed" -ForegroundColor Red
                Write-Log -Message "WinCS Key F33E0C8E002: Query failed" -Level ERROR
            }
        }
    } else {
        $wincsKeyStatus = "WinCsFlagsNotFound"
        Write-Host "WinCS Key F33E0C8E002: WinCsFlags.exe not found" -ForegroundColor Gray
        Write-Log -Message "WinCS Key F33E0C8E002: WinCsFlags.exe not found"
    }
} catch {
    $wincsKeyStatus = "Error"
    Write-Host "WinCS Key F33E0C8E002: Error checking - $_" -ForegroundColor Red
    Write-Log -Message "WinCS Key F33E0C8E002: Error checking - $_" -Level ERROR
}

# =============================================================================
# Remediation Detection - Status Output & Exit Code
# =============================================================================
Write-Log -Message "========================================"
Write-Log -Message "SCRIPT EXECUTION COMPLETE"
Write-Log -Message "========================================"

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
    SkipReasonKnownIssue       = $skipReasonKnownIssue  # KI_<number> from SkipReason in BucketId event
    Event1801Count             = $event1801Count
    Event1808Count             = $event1808Count
    # Error events with captured details
    Event1795Count             = $event1795Count          # Firmware returned error
    Event1795ErrorCode         = $event1795ErrorCode      # Error code from firmware
    Event1796Count             = $event1796Count          # Error code logged
    Event1796ErrorCode         = $event1796ErrorCode      # Captured error code
    Event1800Count             = $event1800Count          # Reboot needed (NOT an error)
    RebootPending              = $rebootPending           # True if Event 1800 present
    Event1802Count             = $event1802Count          # Known firmware issue
    KnownIssueId               = $knownIssueId            # KI_<number> from SkipReason
    Event1803Count             = $event1803Count          # Missing KEK update
    MissingKEK                 = $missingKEK              # OEM needs to supply PK signed KEK
    OSVersion                  = $osVersion
    LastBootTime               = if ($lastBootTime -is [datetime]) { $lastBootTime.ToString("o") } else { "$lastBootTime" }
    BaseBoardManufacturer      = $baseBoardManufacturer
    BaseBoardProduct           = $baseBoardProduct
    SecureBootTaskEnabled      = $secureBootTaskEnabled
    SecureBootTaskStatus       = $secureBootTaskStatus
    WinCSKeyApplied            = $wincsKeyApplied         # True if F33E0C8E002 key is applied
    WinCSKeyStatus             = $wincsKeyStatus          # Applied, NotApplied, WinCsFlagsNotFound, etc.
}

# Output the status - For data aggregation
$jsonOutput = $status | ConvertTo-Json -Compress

# If OutputPath provided, save to file; otherwise output to stdout
if (-not [string]::IsNullOrEmpty($OutputPath)) {
    # Validate OutputPath - skip if it looks like a help request or has invalid chars
    if ($OutputPath -match '^[/\-]' -or $OutputPath -match '[<>:"|?*]') {
        Write-Host "Invalid OutputPath specified, outputting to stdout" -ForegroundColor Yellow
        Write-Log -Message "Invalid OutputPath specified, outputting to stdout" -Level WARNING
        Write-Output $jsonOutput
        Write-Log -Message "Log file saved to: $LogFile"
        if ($secureBootEnabled -and $uefica2023Status -eq "Updated") { 
            Write-Log -Message "RESULT: Device is COMPLIANT - Secure Boot enabled and certificates updated" -Level SUCCESS
            Write-Log -Message "Exit Code: 0 (Without issue)" -Level SUCCESS
            exit 0 
        } else { 
            Write-Log -Message "RESULT: Device requires attention - Review status above" -Level WARNING
            Write-Log -Message "Exit Code: 1 (With issue)" -Level WARNING
            exit 1 
        }
    }
    
    # Ensure the output folder exists
    if (-not (Test-Path $OutputPath)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Log -Message "Created output folder: $OutputPath"
        } catch {
            Write-Warning "Could not create output folder: $OutputPath - $_"
            Write-Log -Message "Could not create output folder: $OutputPath - $_" -Level WARNING
        }
    }
    
    # Save to HOSTNAME_latest.json
    $outputFile = Join-Path $OutputPath "$($hostname)_latest.json"
    try {
        $jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8 -Force
        Write-Host "JSON saved to: $outputFile" -ForegroundColor Green
        Write-Log -Message "JSON saved to: $outputFile" -Level SUCCESS
    } catch {
        Write-Warning "Could not write to file: $outputFile - $_"
        Write-Log -Message "Could not write to file: $outputFile - $_" -Level WARNING
        # Fall back to stdout
        Write-Output $jsonOutput
    }
} else {
    # Original behavior - output to stdout
    Write-Output $jsonOutput
}

# Final summary
Write-Log -Message "Log file saved to: $LogFile"
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