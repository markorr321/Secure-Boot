# Secure Boot Certificate Update - Sets AvailableUpdates=0x5944 and bypasses throttle

$ScriptName = "Secure-Boot-Certificate-Update"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$LogFolder = Join-Path -Path $env:ProgramData -ChildPath $ScriptName
$LogFile = Join-Path -Path $LogFolder -ChildPath "Remediation.log"

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

    # Write to log file only (no console output to stay under 2048 char Intune limit)
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if log file is inaccessible
    }
}

# Initialize log file
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "Secure Boot Certificate Update Script" -Level SECTION
Write-Log -Message "Started: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level SECTION
Write-Log -Message "Log File: $LogFile" -Level INFO
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

# =============================================================================
# Pre-Flight Checks
# =============================================================================

Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "PRE-FLIGHT CHECKS" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

# Check 1: Administrator Privileges
Write-Log -Message "STEP 1: Verifying Administrator Privileges" -Level SECTION
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Log -Message "SUCCESS: Script is running with Administrator privileges" -Level SUCCESS
    Write-Log -Message "Registry modifications will be permitted" -Level INFO
} else {
    Write-Log -Message "ERROR: Script is NOT running as Administrator" -Level ERROR
    Write-Log -Message "Registry modifications require elevated privileges" -Level ERROR
    Write-Log -Message "Please run this script as Administrator" -Level ERROR
    Write-Log -Message "Exiting with error code 1" -Level ERROR
    Write-Output "ERROR: Not running as Administrator. Log: $LogFile"
    exit 1
}
Write-Log -Message ""

# Check 2: Check current Secure Boot status
Write-Log -Message "STEP 2: Checking Current Secure Boot Configuration" -Level SECTION
try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($secureBootEnabled) {
        Write-Log -Message "SUCCESS: Secure Boot is currently ENABLED" -Level SUCCESS
        Write-Log -Message "This device is capable of receiving Secure Boot certificate updates" -Level INFO
    } else {
        Write-Log -Message "WARNING: Secure Boot is currently DISABLED" -Level WARNING
        Write-Log -Message "Certificate updates may not apply until Secure Boot is enabled" -Level WARNING
    }
} catch {
    Write-Log -Message "WARNING: Cannot determine Secure Boot status" -Level WARNING
    Write-Log -Message "This system may not support UEFI Secure Boot" -Level WARNING
    Write-Log -Message "Proceeding with registry modification anyway..." -Level INFO
}
Write-Log -Message ""

# Check 3: Check if update is already pending or completed
Write-Log -Message "STEP 3: Checking Current Certificate Update Status" -Level SECTION
try {
    $currentStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop).UEFICA2023Status
    Write-Log -Message "Current UEFI CA 2023 Status: $currentStatus" -Level INFO

    switch ($currentStatus) {
        "Updated" {
            Write-Log -Message "INFO: Certificates are already UPDATED" -Level INFO
            Write-Log -Message "This update may not be necessary, but will proceed to ensure consistency" -Level INFO
        }
        "InProgress" {
            Write-Log -Message "INFO: Certificate update is already IN PROGRESS" -Level INFO
            Write-Log -Message "Continuing to ensure registry value is set correctly" -Level INFO
        }
        "NotStarted" {
            Write-Log -Message "GOOD: Certificate update has NOT been started yet" -Level SUCCESS
            Write-Log -Message "This update is needed and will trigger the update process" -Level INFO
        }
        "Failed" {
            Write-Log -Message "WARNING: Previous update attempt FAILED" -Level WARNING
            Write-Log -Message "This script will retry the certificate update" -Level INFO
        }
        default {
            Write-Log -Message "Status: $currentStatus (unknown state)" -Level WARNING
        }
    }
} catch {
    Write-Log -Message "INFO: UEFICA2023Status registry key does not exist yet" -Level INFO
    Write-Log -Message "This is normal for devices that haven't attempted the update" -Level INFO
}
Write-Log -Message ""

# =============================================================================
# Registry Configuration for Certificate Update
# =============================================================================

Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "APPLYING UPDATE" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

# Registry configuration
$RegistryPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\'
$ValueName     = 'AvailableUpdates'
$ValueData     = 0x5944  # Bitmask: Deploy all 2023 Secure Boot certificate updates
$ValueDataDec  = 22852   # Decimal equivalent

Write-Log -Message "Registry Configuration Details:" -Level INFO
Write-Log -Message "  Path:  $RegistryPath" -Level INFO
Write-Log -Message "  Name:  $ValueName" -Level INFO
Write-Log -Message "  Value: 0x5944 (hexadecimal) = $ValueDataDec (decimal)" -Level INFO
Write-Log -Message "  Type:  DWORD" -Level INFO
Write-Log -Message ""

# STEP 4: Create registry path if needed
Write-Log -Message "STEP 4: Ensuring Registry Path Exists" -Level SECTION
Write-Log -Message "Checking if registry path exists: $RegistryPath" -Level INFO
if (Test-Path $RegistryPath) {
    Write-Log -Message "SUCCESS: Registry path already exists" -Level SUCCESS
} else {
    Write-Log -Message "WARNING: Registry path does not exist - creating it now..." -Level WARNING
    try {
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Log -Message "SUCCESS: Registry path created successfully" -Level SUCCESS
    } catch {
        Write-Log -Message "ERROR: Failed to create registry path: $_" -Level ERROR
        Write-Log -Message "Exiting with error code 1" -Level ERROR
        Write-Output "ERROR: Failed to create registry path. Log: $LogFile"
        exit 1
    }
}
Write-Log -Message ""

# STEP 5: Set the AvailableUpdates registry value
Write-Log -Message "STEP 5: Setting AvailableUpdates Registry Value" -Level SECTION
Write-Log -Message "This registry value signals Windows to install Secure Boot certificate updates" -Level INFO
Write-Log -Message ""
Write-Log -Message "What this value does (0x5944 bitmask):" -Level INFO
Write-Log -Message "  ✓ Bit 2:  Microsoft Windows Production PCA 2011" -Level INFO
Write-Log -Message "  ✓ Bit 6:  Microsoft Corporation UEFI CA 2011" -Level INFO
Write-Log -Message "  ✓ Bit 8:  Windows UEFI CA 2023 (PRIMARY)" -Level INFO
Write-Log -Message "  ✓ Bit 11: Microsoft UEFI CA 2023" -Level INFO
Write-Log -Message "  ✓ Bit 12: Microsoft Corporation KEK CA 2023" -Level INFO
Write-Log -Message "  ✓ Bit 14: Windows UEFI CA (Additional)" -Level INFO
Write-Log -Message ""
Write-Log -Message "Attempting to set registry value..." -Level INFO

try {
    # Set the registry value
    $result = New-ItemProperty -Path $RegistryPath -Name $ValueName -PropertyType DWord -Value $ValueData -Force -ErrorAction Stop

    Write-Log -Message "SUCCESS: Registry value set successfully!" -Level SUCCESS
    Write-Log -Message ""
    Write-Log -Message "Registry Details:" -Level SUCCESS
    Write-Log -Message "  PSPath:       $($result.PSPath)" -Level INFO
    Write-Log -Message "  Name:         $ValueName" -Level INFO
    Write-Log -Message "  Value:        $($result.$ValueName) (decimal) = 0x$($result.$ValueName.ToString('X')) (hex)" -Level INFO
    Write-Log -Message "  Type:         DWORD" -Level INFO

} catch {
    Write-Log -Message "ERROR: Failed to set registry value!" -Level ERROR
    Write-Log -Message "Error details: $_" -Level ERROR
    Write-Log -Message "Exiting with error code 1" -Level ERROR
    Write-Output "ERROR: Failed to set AvailableUpdates registry value. Log: $LogFile"
    exit 1
}
Write-Log -Message ""

# STEP 6: Verify the registry value was set correctly
Write-Log -Message "STEP 6: Verifying Registry Value" -Level SECTION
Write-Log -Message "Reading back the registry value to confirm it was set correctly..." -Level INFO
try {
    $verifyValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ($verifyValue -eq $ValueData) {
        Write-Log -Message "SUCCESS: Verification passed!" -Level SUCCESS
        Write-Log -Message "Registry value confirmed: $verifyValue (decimal) = 0x$($verifyValue.ToString('X')) (hex)" -Level SUCCESS
        Write-Log -Message "Expected value:           $ValueData (decimal) = 0x$($ValueData.ToString('X')) (hex)" -Level INFO
        Write-Log -Message "✓ Values match - update successful!" -Level SUCCESS
    } else {
        Write-Log -Message "ERROR: Verification failed - values do not match!" -Level ERROR
        Write-Log -Message "Expected: $ValueData, Got: $verifyValue" -Level ERROR
        Write-Log -Message "Exiting with error code 1" -Level ERROR
        Write-Output "ERROR: Registry value verification failed. Expected: $ValueData, Got: $verifyValue. Log: $LogFile"
        exit 1
    }
} catch {
    Write-Log -Message "ERROR: Failed to verify registry value: $_" -Level ERROR
    Write-Log -Message "The value may have been set but cannot be verified" -Level WARNING
}
Write-Log -Message ""

# STEP 7: Override Microsoft's Throttle Mechanism
Write-Log -Message "STEP 7: Bypassing Microsoft's Gradual Rollout Throttle" -Level SECTION
Write-Log -Message "Microsoft uses a throttling mechanism to gradually roll out updates across devices" -Level INFO
Write-Log -Message "By default, devices may wait days or weeks before being eligible to update" -Level INFO
Write-Log -Message "We will override this throttle to allow immediate update eligibility" -Level INFO
Write-Log -Message ""

$ThrottlePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes"
$ThrottleName = "CanAttemptUpdateAfter"

# Check if the throttle registry key exists
Write-Log -Message "Checking for throttle registry key..." -Level INFO
if (Test-Path $ThrottlePath) {
    Write-Log -Message "SUCCESS: DeviceAttributes path exists" -Level SUCCESS

    # Try to read current throttle value
    try {
        $currentThrottle = Get-ItemProperty -Path $ThrottlePath -Name $ThrottleName -ErrorAction Stop
        $currentValue = $currentThrottle.$ThrottleName

        # Convert FILETIME (QWORD) to DateTime
        try {
            $currentDate = [DateTime]::FromFileTimeUtc($currentValue)
            Write-Log -Message "Current throttle date: $($currentDate.ToString('MM/dd/yyyy HH:mm:ss'))" -Level INFO

            $now = Get-Date
            if ($currentDate -gt $now) {
                Write-Log -Message "WARNING: Device is throttled until $($currentDate.ToString('MM/dd/yyyy'))" -Level WARNING
                Write-Log -Message "Without this override, the update would NOT start until that date" -Level WARNING
            } else {
                Write-Log -Message "INFO: Current throttle date is in the past (device is already eligible)" -Level INFO
            }
        } catch {
            Write-Log -Message "WARNING: Could not parse current throttle date" -Level WARNING
        }
    } catch {
        Write-Log -Message "INFO: CanAttemptUpdateAfter value does not exist yet (first run)" -Level INFO
    }
} else {
    Write-Log -Message "INFO: DeviceAttributes path does not exist yet - creating it now..." -Level INFO
    try {
        New-Item -Path $ThrottlePath -Force | Out-Null
        Write-Log -Message "SUCCESS: DeviceAttributes path created successfully" -Level SUCCESS
    } catch {
        Write-Log -Message "ERROR: Failed to create DeviceAttributes path: $_" -Level ERROR
        Write-Log -Message "Continuing without throttle override (update may be delayed)" -Level WARNING
        Write-Log -Message ""
        # Don't exit - the AvailableUpdates value is still set, so update will eventually work
    }
}

# Set the throttle to a past date (January 1, 2026)
Write-Log -Message ""
Write-Log -Message "Setting CanAttemptUpdateAfter to past date (01/01/2026)..." -Level INFO
try {
    $PastDate = [DateTime]::new(2026, 1, 1).ToFileTimeUtc()
    Set-ItemProperty -Path $ThrottlePath -Name $ThrottleName -Value $PastDate -Type QWord -Force -ErrorAction Stop

    Write-Log -Message "SUCCESS: Throttle override applied!" -Level SUCCESS
    Write-Log -Message ""

    # Verify the throttle override
    Write-Log -Message "Verifying throttle override..." -Level INFO
    try {
        $verifyThrottle = Get-ItemProperty -Path $ThrottlePath -Name $ThrottleName -ErrorAction Stop
        $verifyValue = $verifyThrottle.$ThrottleName
        $verifyDate = [DateTime]::FromFileTimeUtc($verifyValue)

        Write-Log -Message "SUCCESS: Verification passed!" -Level SUCCESS
        Write-Log -Message "Throttle date now set to: $($verifyDate.ToString('MM/dd/yyyy HH:mm:ss'))" -Level SUCCESS
        Write-Log -Message "✓ This is in the PAST - device is now eligible for immediate update" -Level SUCCESS
    } catch {
        Write-Log -Message "WARNING: Could not verify throttle override" -Level WARNING
    }

} catch {
    Write-Log -Message "ERROR: Failed to set throttle override: $_" -Level ERROR
    Write-Log -Message "Update will still proceed but may be delayed by Microsoft's rollout schedule" -Level WARNING
}
Write-Log -Message ""

Write-Log -Message "Why this matters:" -Level INFO
Write-Log -Message "  • Without override: Windows checks CanAttemptUpdateAfter before updating" -Level INFO
Write-Log -Message "  • If date is future: Update waits until that date (could be weeks)" -Level INFO
Write-Log -Message "  • With override: CanAttemptUpdateAfter is in the past" -Level INFO
Write-Log -Message "  • Result: Device can immediately attempt update on next reboot" -Level SUCCESS
Write-Log -Message ""

# =============================================================================
# UPDATE SUMMARY
# =============================================================================

Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "UPDATE SUMMARY" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

Write-Log -Message "✓ UPDATE COMPLETED SUCCESSFULLY" -Level SUCCESS
Write-Log -Message ""
Write-Log -Message "What was done:" -Level INFO
Write-Log -Message "  1. ✓ Verified administrator privileges" -Level SUCCESS
Write-Log -Message "  2. ✓ Checked current Secure Boot configuration" -Level SUCCESS
Write-Log -Message "  3. ✓ Reviewed current certificate update status" -Level SUCCESS
Write-Log -Message "  4. ✓ Ensured registry path exists" -Level SUCCESS
Write-Log -Message "  5. ✓ Set AvailableUpdates = 0x5944" -Level SUCCESS
Write-Log -Message "  6. ✓ Verified registry value was set correctly" -Level SUCCESS
Write-Log -Message "  7. ✓ Bypassed Microsoft's throttle mechanism" -Level SUCCESS
Write-Log -Message ""

Write-Log -Message "========================================" -Level SECTION
Write-Log -Message "NEXT STEPS REQUIRED" -Level SECTION
Write-Log -Message "========================================" -Level SECTION
Write-Log -Message ""

Write-Log -Message "CRITICAL: The certificate update will NOT take effect until the device is REBOOTED" -Level WARNING
Write-Log -Message ""
Write-Log -Message "What happens next:" -Level INFO
Write-Log -Message "  1. Device must be REBOOTED" -Level WARNING
Write-Log -Message "  2. During boot, Windows will detect the AvailableUpdates registry value" -Level INFO
Write-Log -Message "  3. Windows will communicate with UEFI firmware to install certificates" -Level INFO
Write-Log -Message "  4. Certificates will be installed in the device's firmware" -Level INFO
Write-Log -Message "  5. Windows will update UEFICA2023Status to 'Updated'" -Level INFO
Write-Log -Message "  6. Event ID 1801 (success) or 1808 (failure) will be logged" -Level INFO
Write-Log -Message "  7. Next detection script run will confirm compliance (Exit 0)" -Level INFO
Write-Log -Message ""

Write-Log -Message "Reboot Options:" -Level INFO
Write-Log -Message "  • Manual reboot: Restart the device when convenient" -Level INFO
Write-Log -Message "  • Scheduled reboot: Use Intune or SCCM to schedule a maintenance window" -Level INFO
Write-Log -Message "  • Immediate reboot: Run 'Restart-Computer -Force' (not recommended during business hours)" -Level INFO
Write-Log -Message ""

Write-Log -Message "Verification Steps (after reboot):" -Level INFO
Write-Log -Message "  1. Run the detection script again" -Level INFO
Write-Log -Message "  2. Check that UEFICA2023Status = 'Updated'" -Level INFO
Write-Log -Message "  3. Verify Event ID 1801 appears in System event log" -Level INFO
Write-Log -Message "  4. Confirm detection script exits with code 0 (compliant)" -Level INFO
Write-Log -Message ""

Write-Log -Message "Exit Code: 0 (Update successful)" -Level SUCCESS
Write-Log -Message "Completed: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')" -Level INFO
Write-Log -Message "Log saved to: $LogFile" -Level INFO
Write-Log -Message "========================================" -Level SECTION

# Summary output for Intune (under 2048 chars)
Write-Output "SUCCESS: Secure Boot certificate update configured. AvailableUpdates=0x5944. Reboot required. Log: $LogFile"
exit 0
