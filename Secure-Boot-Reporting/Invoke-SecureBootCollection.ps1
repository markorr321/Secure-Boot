<#
.SYNOPSIS
Collect Secure Boot certificate status and upload to Log Analytics via Azure Function.

.DESCRIPTION
This script collects Secure Boot status, UEFI CA 2023 certificate update state, device attributes,
and event log data from Windows devices. Data is sent to an Azure Function which forwards it to
Log Analytics for fleet-wide Secure Boot compliance monitoring.

Designed to run as an Intune Proactive Remediation (Detection script) or as a scheduled task.

Exit 0 = Compliant (Secure Boot enabled + certificates updated)
Exit 1 = Non-compliant (informational only)

Source: https://support.microsoft.com/en-us/topic/sample-secure-boot-inventory-data-collection-script-d02971d2-d4b5-42c9-b58a-8527f0ffa30b

.EXAMPLE
Invoke-SecureBootCollection.ps1 (Required to run as System or Administrator)
#>

#region initialize
# Define your Azure Function URL:
$AzureFunctionURL = "https://YOUR-FUNCTION-APP-NAME.azurewebsites.net/api/logcollectorapi"

# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$CollectSecureBootInventory = $true
$SecureBootLogName = "SecureBootInventory"
$Date = Get-Date
#endregion initialize

#region functions
function Get-AzureADDeviceID {
    Process {
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoKey -ne $null) {
            if ($AzureADJoinInfoKey -ne $null) {
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }
                }
            }
            if ($AzureADJoinCertificate -ne $null) {
                $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                return $AzureADDeviceID
            }
        }
    }
}

function Get-AzureADTenantID {
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
}
#endregion functions

#region script
#region common
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

# Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
    $MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'MS DM Server' }
    $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)" -ErrorAction SilentlyContinue
}
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$ComputerName = $env:COMPUTERNAME
#endregion common

#region SECUREBOOTINVENTORY
if ($CollectSecureBootInventory) {

    # --- Secure Boot Status ---
    try {
        $SecureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    } catch {
        try {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
            $SecureBootEnabled = [bool]$regValue.UEFISecureBootEnabled
        } catch {
            $SecureBootEnabled = $null
        }
    }

    # --- SecureBoot Registry: Main Key ---
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop
        $HighConfidenceOptOut = $regValue.HighConfidenceOptOut
    } catch {
        $HighConfidenceOptOut = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop
        $AvailableUpdates = $regValue.AvailableUpdates
        if ($null -ne $AvailableUpdates) {
            $AvailableUpdatesHex = "0x{0:X}" -f $AvailableUpdates
        } else {
            $AvailableUpdatesHex = $null
        }
    } catch {
        $AvailableUpdates = $null
        $AvailableUpdatesHex = $null
    }

    # --- SecureBoot Registry: Servicing Key ---
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop
        $UEFICA2023Status = $regValue.UEFICA2023Status
    } catch {
        $UEFICA2023Status = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop
        $UEFICA2023Error = $regValue.UEFICA2023Error
    } catch {
        $UEFICA2023Error = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop
        $UEFICA2023ErrorEvent = $regValue.UEFICA2023ErrorEvent
    } catch {
        $UEFICA2023ErrorEvent = $null
    }

    # --- Device Attributes ---
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop
        $OEMManufacturerName = $regValue.OEMManufacturerName
    } catch {
        $OEMManufacturerName = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelSystemFamily -ErrorAction Stop
        $OEMModelSystemFamily = $regValue.OEMModelSystemFamily
    } catch {
        $OEMModelSystemFamily = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelNumber -ErrorAction Stop
        $OEMModelNumber = $regValue.OEMModelNumber
    } catch {
        $OEMModelNumber = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareVersion -ErrorAction Stop
        $FirmwareVersion = $regValue.FirmwareVersion
    } catch {
        $FirmwareVersion = $null
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareReleaseDate -ErrorAction Stop
        $FirmwareReleaseDate = $regValue.FirmwareReleaseDate
    } catch {
        $FirmwareReleaseDate = $null
    }

    $OSArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($OSArchitecture)) {
        try {
            $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OSArchitecture -ErrorAction Stop
            $OSArchitecture = $regValue.OSArchitecture
        } catch {
            $OSArchitecture = "Unknown"
        }
    }

    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name CanAttemptUpdateAfter -ErrorAction Stop
        $CanAttemptUpdateAfter = $regValue.CanAttemptUpdateAfter
        if ($null -ne $CanAttemptUpdateAfter) {
            try {
                if ($CanAttemptUpdateAfter -is [byte[]]) {
                    $fileTime = [BitConverter]::ToInt64($CanAttemptUpdateAfter, 0)
                    $CanAttemptUpdateAfter = [DateTime]::FromFileTime($fileTime).ToUniversalTime().ToString("o")
                } elseif ($CanAttemptUpdateAfter -is [long]) {
                    $CanAttemptUpdateAfter = [DateTime]::FromFileTime($CanAttemptUpdateAfter).ToUniversalTime().ToString("o")
                } else {
                    $CanAttemptUpdateAfter = "$CanAttemptUpdateAfter"
                }
            } catch {
                $CanAttemptUpdateAfter = "$CanAttemptUpdateAfter"
            }
        }
    } catch {
        $CanAttemptUpdateAfter = $null
    }

    # --- Event Log Data ---
    try {
        $allEventIds = @(1801, 1808)
        $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 20 -ErrorAction Stop)

        if ($events.Count -eq 0) {
            $LatestEventId = $null
            $BucketId = $null
            $Confidence = $null
            $Event1801Count = 0
            $Event1808Count = 0
        } else {
            $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $LatestEventId = if ($null -ne $latestEvent) { "$($latestEvent.Id)" } else { $null }

            if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
                $BucketId = if ($latestEvent.Message -match 'BucketId:\s*(.+)') { $matches[1].Trim() } else { $null }
                $Confidence = if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') { $matches[1].Trim() } else { $null }
            } else {
                $BucketId = $null
                $Confidence = $null
            }

            $Event1801Count = @($events | Where-Object {$_.Id -eq 1801}).Count
            $Event1808Count = @($events | Where-Object {$_.Id -eq 1808}).Count
        }
    } catch {
        $LatestEventId = $null
        $BucketId = $null
        $Confidence = $null
        $Event1801Count = 0
        $Event1808Count = 0
    }

    # --- System Info ---
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $OSVersion = $osInfo.Version
        $LastBootTime = $osInfo.LastBootUpTime.ToString("o")
    } catch {
        $OSVersion = "Unknown"
        $LastBootTime = $null
    }

    try {
        $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        $BaseBoardManufacturer = $baseBoard.Manufacturer
        $BaseBoardProduct = $baseBoard.Product
    } catch {
        $BaseBoardManufacturer = "Unknown"
        $BaseBoardProduct = "Unknown"
    }

    # Determine compliance
    $IsCompliant = ($SecureBootEnabled -eq $true -and $UEFICA2023Status -eq "Updated")

    # Build inventory object
    $Inventory = New-Object System.Object
    $Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "SecureBootEnabled" -Value "$SecureBootEnabled" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "UEFICA2023Status" -Value "$UEFICA2023Status" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "UEFICA2023Error" -Value "$UEFICA2023Error" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "UEFICA2023ErrorEvent" -Value "$UEFICA2023ErrorEvent" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "AvailableUpdates" -Value "$AvailableUpdatesHex" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "HighConfidenceOptOut" -Value "$HighConfidenceOptOut" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OEMManufacturerName" -Value "$OEMManufacturerName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OEMModelSystemFamily" -Value "$OEMModelSystemFamily" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OEMModelNumber" -Value "$OEMModelNumber" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareVersion" -Value "$FirmwareVersion" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareReleaseDate" -Value "$FirmwareReleaseDate" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OSArchitecture" -Value "$OSArchitecture" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "CanAttemptUpdateAfter" -Value "$CanAttemptUpdateAfter" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "LatestEventId" -Value "$LatestEventId" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BucketId" -Value "$BucketId" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Confidence" -Value "$Confidence" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Event1801Count" -Value "$Event1801Count" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Event1808Count" -Value "$Event1808Count" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OSVersion" -Value "$OSVersion" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "LastBootTime" -Value "$LastBootTime" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BaseBoardManufacturer" -Value "$BaseBoardManufacturer" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BaseBoardProduct" -Value "$BaseBoardProduct" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "IsCompliant" -Value "$IsCompliant" -Force

    $SecureBootInventory = $Inventory
}
#endregion SECUREBOOTINVENTORY

#region compose
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "CollectionDate:$date "

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

$LogPayLoad = New-Object -TypeName PSObject
if ($CollectSecureBootInventory) {
    $LogPayLoad | Add-Member -NotePropertyMembers @{$SecureBootLogName = $SecureBootInventory}
}

$MainPayLoad = [PSCustomObject]@{
    AzureADTenantID = $AzureADTenantID
    AzureADDeviceID = $AzureADDeviceID
    LogPayloads = $LogPayLoad
}
$MainPayLoadJson = $MainPayLoad | ConvertTo-Json -Depth 9
#endregion compose

#region ingestion
$ExitCode = 0

try {
    $ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson
    foreach ($response in $ResponseInventory) {
        if ($response.response -match "200") {
            $OutputMessage = $OutputMessage + "OK: $($response.logname) $($response.response) "
        }
        else {
            $OutputMessage = $OutputMessage + "FAIL: $($response.logname) $($response.response) "
            $ExitCode = 1
        }
    }
}
catch {
    $ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
    $ResponseMessage = $_.Exception.Message
    $OutputMessage = $OutputMessage + "Inventory:FAIL " + $ResponseInventory + $ResponseMessage
    $ExitCode = 1
}

Write-Output $OutputMessage

# Set exit code based on compliance (for Intune Remediation detection)
if (-not $IsCompliant) {
    $ExitCode = 1
}

Exit $ExitCode
#endregion ingestion
#endregion script
