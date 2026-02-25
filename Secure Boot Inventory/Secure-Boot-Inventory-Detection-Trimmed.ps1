$ScriptName = "Secure-Boot-Inventory-Detection"
$LogFolder = Join-Path -Path $env:ProgramData -ChildPath $ScriptName
$LogFile = Join-Path -Path $LogFolder -ChildPath "Detection.log"
try { if (-not (Test-Path -Path $LogFolder)) { New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null } } catch { }

function Write-Log {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message,[Parameter(Mandatory=$false)][ValidateSet('INFO','SUCCESS','WARNING','ERROR','SECTION')][string]$Level = 'INFO',[Parameter(Mandatory=$false)][switch]$NoConsole)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    $Color = switch ($Level) { 'SUCCESS' { 'Green' } 'WARNING' { 'Yellow' } 'ERROR' { 'Red' } 'SECTION' { 'Cyan' } default { 'White' } }
    if (-not $NoConsole) { Write-Host $LogEntry -ForegroundColor $Color }
    try { Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue } catch { }
}

Write-Log -Message "Secure Boot Certificate Detection Started" -Level SECTION

try { $hostname = $env:COMPUTERNAME; if ([string]::IsNullOrEmpty($hostname)) { $hostname = "Unknown" } } catch { $hostname = "Error" }
Write-Host "Hostname: $hostname"

try { $collectionTime = Get-Date } catch { $collectionTime = "Error" }

try {
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
        $secureBootEnabled = [bool]$regValue.UEFISecureBootEnabled
    } catch { $secureBootEnabled = $null }
}
Write-Host "Secure Boot Enabled: $secureBootEnabled"

try { $highConfidenceOptOut = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop).HighConfidenceOptOut } catch { $highConfidenceOptOut = $null }
Write-Host "High Confidence Opt Out: $highConfidenceOptOut"

try {
    $availableUpdates = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop).AvailableUpdates
    if ($null -ne $availableUpdates) { $availableUpdatesHex = "0x{0:X}" -f $availableUpdates }
} catch { $availableUpdates = $null }
Write-Host "Available Updates: $(if ($null -ne $availableUpdates) { $availableUpdatesHex } else { 'Not Available' })"

try { $uefica2023Status = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop).UEFICA2023Status } catch { $uefica2023Status = $null }
Write-Host "UEFI CA 2023 Status: $uefica2023Status"

try { $uefica2023Error = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop).UEFICA2023Error } catch { $uefica2023Error = $null }
Write-Host "UEFI CA 2023 Error: $uefica2023Error"

try { $uefica2023ErrorEvent = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop).UEFICA2023ErrorEvent } catch { $uefica2023ErrorEvent = $null }
Write-Host "UEFI CA 2023 Error Event: $uefica2023ErrorEvent"

try { $oemManufacturerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop).OEMManufacturerName; if ([string]::IsNullOrEmpty($oemManufacturerName)) { $oemManufacturerName = "Unknown" } } catch { $oemManufacturerName = $null }
Write-Host "OEM Manufacturer Name: $oemManufacturerName"

try { $oemModelSystemFamily = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelSystemFamily -ErrorAction Stop).OEMModelSystemFamily; if ([string]::IsNullOrEmpty($oemModelSystemFamily)) { $oemModelSystemFamily = "Unknown" } } catch { $oemModelSystemFamily = $null }
Write-Host "OEM Model System Family: $oemModelSystemFamily"

try { $oemModelNumber = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelNumber -ErrorAction Stop).OEMModelNumber; if ([string]::IsNullOrEmpty($oemModelNumber)) { $oemModelNumber = "Unknown" } } catch { $oemModelNumber = $null }
Write-Host "OEM Model Number: $oemModelNumber"

try { $firmwareVersion = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareVersion -ErrorAction Stop).FirmwareVersion; if ([string]::IsNullOrEmpty($firmwareVersion)) { $firmwareVersion = "Unknown" } } catch { $firmwareVersion = $null }
Write-Host "Firmware Version: $firmwareVersion"

try { $firmwareReleaseDate = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareReleaseDate -ErrorAction Stop).FirmwareReleaseDate; if ([string]::IsNullOrEmpty($firmwareReleaseDate)) { $firmwareReleaseDate = "Unknown" } } catch { $firmwareReleaseDate = $null }
Write-Host "Firmware Release Date: $firmwareReleaseDate"

try { $osArchitecture = $env:PROCESSOR_ARCHITECTURE; if ([string]::IsNullOrEmpty($osArchitecture)) { $osArchitecture = "Unknown" } } catch { $osArchitecture = "Unknown" }
Write-Host "OS Architecture: $osArchitecture"

try {
    $canAttemptUpdateAfter = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name CanAttemptUpdateAfter -ErrorAction Stop).CanAttemptUpdateAfter
    if ($null -ne $canAttemptUpdateAfter) {
        try {
            if ($canAttemptUpdateAfter -is [byte[]]) { $fileTime = [BitConverter]::ToInt64($canAttemptUpdateAfter, 0); $canAttemptUpdateAfter = [DateTime]::FromFileTime($fileTime).ToUniversalTime() }
            elseif ($canAttemptUpdateAfter -is [long]) { $canAttemptUpdateAfter = [DateTime]::FromFileTime($canAttemptUpdateAfter).ToUniversalTime() }
        } catch { }
    }
} catch { $canAttemptUpdateAfter = $null }
Write-Host "Can Attempt Update After: $canAttemptUpdateAfter"

try {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(1801, 1808)} -MaxEvents 20 -ErrorAction Stop)
    if ($events.Count -eq 0) { $latestEventId = $null; $bucketId = $null; $confidence = $null; $event1801Count = 0; $event1808Count = 0 }
    else {
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $latestEventId = if ($null -ne $latestEvent) { $latestEvent.Id } else { $null }
        $bucketId = if ($null -ne $latestEvent -and $latestEvent.Message -match 'BucketId:\s*(.+)') { $matches[1].Trim() } else { $null }
        $confidence = if ($null -ne $latestEvent -and $latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') { $matches[1].Trim() } else { $null }
        $event1801Count = @($events | Where-Object {$_.Id -eq 1801}).Count
        $event1808Count = @($events | Where-Object {$_.Id -eq 1808}).Count
    }
} catch { $latestEventId = $null; $bucketId = $null; $confidence = $null; $event1801Count = 0; $event1808Count = 0 }
Write-Host "Latest Event ID: $latestEventId"
Write-Host "Bucket ID: $bucketId"
Write-Host "Confidence: $confidence"
Write-Host "Event 1801 Count: $event1801Count"
Write-Host "Event 1808 Count: $event1808Count"

try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $osVersion = if ($null -ne $osInfo -and -not [string]::IsNullOrEmpty($osInfo.Version)) { $osInfo.Version } else { "Unknown" }; $lastBootTime = $osInfo.LastBootUpTime } catch { $osVersion = "Unknown"; $lastBootTime = $null }
Write-Host "OS Version: $osVersion"
Write-Host "Last Boot Time: $lastBootTime"

try { $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop; $baseBoardManufacturer = if ($null -ne $baseBoard -and -not [string]::IsNullOrEmpty($baseBoard.Manufacturer)) { $baseBoard.Manufacturer } else { "Unknown" }; $baseBoardProduct = if ($null -ne $baseBoard -and -not [string]::IsNullOrEmpty($baseBoard.Product)) { $baseBoard.Product } else { "Unknown" } } catch { $baseBoardManufacturer = "Unknown"; $baseBoardProduct = "Unknown" }
Write-Host "Baseboard Manufacturer: $baseBoardManufacturer"
Write-Host "Baseboard Product: $baseBoardProduct"

$status = [ordered]@{
    UEFICA2023Status = $uefica2023Status; UEFICA2023Error = $uefica2023Error; UEFICA2023ErrorEvent = $uefica2023ErrorEvent
    AvailableUpdates = if ($null -ne $availableUpdates) { $availableUpdatesHex } else { $null }
    Hostname = $hostname; CollectionTime = if ($collectionTime -is [datetime]) { $collectionTime.ToString("o") } else { "$collectionTime" }
    SecureBootEnabled = $secureBootEnabled; HighConfidenceOptOut = $highConfidenceOptOut
    OEMManufacturerName = $oemManufacturerName; OEMModelSystemFamily = $oemModelSystemFamily; OEMModelNumber = $oemModelNumber
    FirmwareVersion = $firmwareVersion; FirmwareReleaseDate = $firmwareReleaseDate; OSArchitecture = $osArchitecture
    CanAttemptUpdateAfter = if ($canAttemptUpdateAfter -is [datetime]) { $canAttemptUpdateAfter.ToString("o") } else { "$canAttemptUpdateAfter" }
    LatestEventId = $latestEventId; BucketId = $bucketId; Confidence = $confidence; Event1801Count = $event1801Count; Event1808Count = $event1808Count
    OSVersion = $osVersion; LastBootTime = if ($lastBootTime -is [datetime]) { $lastBootTime.ToString("o") } else { "$lastBootTime" }
    BaseBoardManufacturer = $baseBoardManufacturer; BaseBoardProduct = $baseBoardProduct
}

$jsonOutput = $status | ConvertTo-Json -Compress
Write-Output $jsonOutput
Write-Log -Message "JSON: $jsonOutput" -Level INFO

if ($secureBootEnabled -and $uefica2023Status -eq "Updated") {
    Write-Log -Message "COMPLIANT: Secure Boot enabled and certificates updated" -Level SUCCESS
    exit 0
} else {
    Write-Log -Message "NON-COMPLIANT: SecureBoot=$secureBootEnabled, Status=$uefica2023Status" -Level WARNING
    exit 1
}
