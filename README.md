# Secure Boot Certificate Update Deployment Scripts

PowerShell scripts for deploying Microsoft's Windows UEFI CA 2023 Secure Boot certificate updates across enterprise environments via Microsoft Intune. Implements Microsoft's "Option 3 - Self-Managed Rollout" approach with automated throttle bypass for immediate deployment.

## Overview

These scripts automate the detection and remediation of outdated Secure Boot certificates on Windows 10/11 devices, addressing:
- ✅ **Certificate Expiration**: 2011-era certificates expiring in 2025-2026
- ✅ **BlackLotus Vulnerability**: Mitigation for CVE-2023-24932 bootkit attacks
- ✅ **Windows Update Compatibility**: Ensures future security updates can be installed

## What's Included

### 📊 Detection Script
**`Secure Boot Inventory/Secure-Boot-Inventory-Data-Collection-Detection.ps1`**
- Collects 24 data points about Secure Boot status and certificate compliance
- Outputs structured JSON for reporting and dashboard creation
- Verbose logging with plain English explanations
- Exits with 0 (compliant) or 1 (non-compliant) for Intune Proactive Remediations

**Data Points Collected:**
1. UEFICA2023Status (NotStarted/InProgress/Updated/Failed)
2. UEFICA2023Error (error code if any)
3. UEFICA2023ErrorEvent (event log details)
4. AvailableUpdates (registry bitmask value)
5. Hostname (device identifier)
6. CollectionTime (timestamp)
7. SecureBootEnabled (true/false)
8. HighConfidenceOptOut (registry value)
9. OEMManufacturerName (Dell, HP, Lenovo, etc.)
10. OEMModelSystemFamily (device family)
11. OEMModelNumber (specific model)
12. FirmwareVersion (BIOS version)
13. FirmwareReleaseDate (BIOS date)
14. OSArchitecture (32-bit/64-bit)
15. CanAttemptUpdateAfter (throttle date)
16. LatestEventId (most recent event)
17. BucketId (telemetry bucket)
18. Confidence (telemetry confidence level)
19. Event1801Count (success events)
20. Event1808Count (failure events)
21. OSVersion (Windows version)
22. LastBootTime (device uptime)
23. BaseBoardManufacturer (motherboard OEM)
24. BaseBoardProduct (motherboard model)

### 🔧 Remediation Script
**`Secure Boot Remediation/Deploy-SecureBootCert-SelfRollout.ps1`**
- Sets `AvailableUpdates = 0x5944` registry value to trigger certificate updates
- Bypasses Microsoft's gradual rollout throttle mechanism for immediate deployment
- Comprehensive pre-flight checks and verification steps
- Verbose logging to `C:\Windows\Temp\Secure-Boot-Remediation_<timestamp>/`

**Remediation Steps:**
1. Verifies Administrator privileges
2. Checks current Secure Boot configuration
3. Reviews current certificate update status
4. Ensures registry path exists
5. Sets AvailableUpdates = 0x5944 (certificate bitmask)
6. Verifies registry value was set correctly
7. Bypasses Microsoft's throttle mechanism (sets CanAttemptUpdateAfter to past date)

## Key Features

- **🚀 Throttle Bypass**: Overrides `CanAttemptUpdateAfter` to enable immediate updates (no waiting for Microsoft's rollout)
- **📝 Comprehensive Logging**: Timestamped logs with color-coded output levels (INFO, SUCCESS, WARNING, ERROR)
- **🔍 24 Data Points**: Collects firmware version, OEM info, event logs, certificate status, throttle dates, and more
- **🏢 Enterprise-Ready**: Designed for Intune deployment with independent detection/remediation workflow
- **🔒 Safe & Non-Destructive**: Registry-based approach works across all OEM vendors (Dell, HP, Lenovo, Surface, etc.)
- **📊 JSON Output**: Structured data for Log Analytics, Power BI dashboards, and compliance reporting

## Prerequisites

- **Secure Boot Enabled**: Devices must have UEFI Secure Boot enabled (enforce via Intune compliance policy)
- **UEFI Firmware**: Legacy BIOS systems not supported
- **Windows 10/11**: Any version with Secure Boot support
- **Administrator Rights**: Scripts must run as SYSTEM or Administrator
- **Intune Licensing**: Microsoft Intune or Configuration Manager

## Deployment Workflow

### Phase 1: Data Collection & Assessment
1. Deploy detection script to all devices (or pilot group)
2. Schedule runs (e.g., daily or weekly)
3. Export JSON output from Intune console or Log Analytics
4. Build report/dashboard to identify eligible devices
5. Filter for: `SecureBootEnabled = true` AND `UEFICA2023Status != "Updated"`

### Phase 2: Targeted Remediation
1. Create device group or Intune filter based on detection results
2. Deploy remediation script to eligible devices only
3. Schedule reboot (or wait for natural reboot cycle)
4. Certificate updates apply during boot process

### Phase 3: Verification
1. Re-run detection script after reboot
2. Confirm: `UEFICA2023Status = "Updated"`
3. Verify: `AvailableUpdates = "0x4000"` or `"0x4100"`
4. Check: Event ID 1801 (success) appears in System event log
5. Validate: Detection script exits with code 0 (compliant)

## Intune Configuration

### Detection Script Setup
**Intune → Devices → Scripts and remediations → Proactive remediations**

Create **Detection-Only** policy:
- **Name:** `Secure Boot Certificate Inventory`
- **Detection script:** `Secure-Boot-Inventory-Data-Collection-Detection.ps1`
- **Remediation script:** *(Leave blank or upload dummy script)*
- **Run script in 64-bit PowerShell:** Yes
- **Run with logged on credentials:** No (run as SYSTEM)
- **Schedule:** Daily at midnight
- **Assignment:** All Windows devices (or pilot group)

### Remediation Script Setup
**Intune → Devices → Scripts → Platform scripts**

Create **Remediation** policy:
- **Name:** `Deploy Secure Boot Certificate Update`
- **Script:** `Deploy-SecureBootCert-SelfRollout.ps1`
- **Run script in 64-bit PowerShell:** Yes
- **Run with logged on credentials:** No (run as SYSTEM)
- **Enforce script signature check:** No
- **Assignment:** Only devices identified by detection script
- **Schedule:** Run once, or on a schedule

## Registry Values Modified

| Registry Path | Value Name | Type | Value | Purpose |
|---------------|------------|------|-------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot` | `AvailableUpdates` | DWORD | `0x5944` (22852) | Bitmask that triggers certificate deployment |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes` | `CanAttemptUpdateAfter` | QWORD | FILETIME (01/01/2026) | Bypasses Microsoft's gradual rollout throttle |

## The 0x5944 Bitmask Explained

```
0x5944 = 22852 (decimal) = 0101 1001 0100 0100 (binary)

This bitmask instructs Windows to update the following Secure Boot certificate authorities:
  • Bit 2  (0x0004): Microsoft Windows Production PCA 2011
  • Bit 6  (0x0040): Microsoft Corporation UEFI CA 2011
  • Bit 8  (0x0100): Windows UEFI CA 2023 (PRIMARY)
  • Bit 11 (0x0800): Microsoft UEFI CA 2023
  • Bit 12 (0x1000): Microsoft Corporation KEK CA 2023
  • Bit 14 (0x4000): Windows UEFI CA (Additional)

This combination ensures all required 2023-era certificates are deployed to address:
  ✓ Certificate expiration (2011 certificates expiring)
  ✓ BlackLotus bootkit vulnerability mitigation
  ✓ Future Windows security update compatibility
```

## Sample Output

### Detection Script JSON Output
```json
{
  "UEFICA2023Status": "NotStarted",
  "UEFICA2023Error": null,
  "UEFICA2023ErrorEvent": null,
  "AvailableUpdates": "0x0",
  "Hostname": "LAPTOP-ABC123",
  "CollectionTime": "2026-02-16T14:30:00.0000000Z",
  "SecureBootEnabled": true,
  "HighConfidenceOptOut": "0x0",
  "OEMManufacturerName": "Dell Inc.",
  "OEMModelSystemFamily": "Latitude",
  "OEMModelNumber": "Latitude 5450",
  "FirmwareVersion": "1.25.0",
  "FirmwareReleaseDate": "2025-11-15",
  "OSArchitecture": "64-bit",
  "CanAttemptUpdateAfter": "2026-02-22T22:41:58.0000000Z",
  "LatestEventId": null,
  "BucketId": null,
  "Confidence": null,
  "Event1801Count": 0,
  "Event1808Count": 0,
  "OSVersion": "Microsoft Windows 11 Pro",
  "LastBootTime": "2026-02-16T08:15:00.0000000Z",
  "BaseBoardManufacturer": "Dell Inc.",
  "BaseBoardProduct": "0XGVW8"
}
```

### Remediation Script Verbose Logging
```
[2026-02-16 14:30:00] [SECTION] ========================================
[2026-02-16 14:30:00] [SECTION] Secure Boot Certificate Remediation Script
[2026-02-16 14:30:00] [SECTION] ========================================
[2026-02-16 14:30:00] [SUCCESS] Script is running with Administrator privileges
[2026-02-16 14:30:00] [SUCCESS] Secure Boot is currently ENABLED
[2026-02-16 14:30:00] [INFO] Current UEFI CA 2023 Status: NotStarted
[2026-02-16 14:30:00] [SUCCESS] Registry value set successfully!
[2026-02-16 14:30:00] [SUCCESS] Registry value confirmed: 22852 (decimal) = 0x5944 (hex)
[2026-02-16 14:30:01] [SUCCESS] Throttle override applied!
[2026-02-16 14:30:01] [SUCCESS] Throttle date now set to: 01/01/2026 00:00:00
[2026-02-16 14:30:01] [SUCCESS] ✓ This is in the PAST - device is now eligible for immediate update
[2026-02-16 14:30:01] [WARNING] CRITICAL: The certificate update will NOT take effect until the device is REBOOTED
```

## Log Files Location

Both scripts create timestamped log folders for troubleshooting:

**Detection Script:**
```
C:\Windows\Temp\Secure-Boot-Detection_<yyyy-MM-dd_HHmmss>\logfile_<yyyy-MM-dd_HHmmss>.log
```

**Remediation Script:**
```
C:\Windows\Temp\Secure-Boot-Remediation_<yyyy-MM-dd_HHmmss>\logfile_<yyyy-MM-dd_HHmmss>.log
```

## Monitoring Success

### Compliance Indicators
After remediation + reboot, verify via detection script:
- ✅ `UEFICA2023Status` = **"Updated"**
- ✅ `AvailableUpdates` = **"0x4000"** or **"0x4100"**
- ✅ Event ID **1801** (success) logged in System event log
- ✅ Exit Code = **0** (compliant)

### Expected Timeline
1. **T+0**: Remediation script runs, sets registry values
2. **T+1 hour**: Device reboots (scheduled or natural)
3. **T+1 hour + 5 min**: Windows applies certificate updates during boot
4. **T+1 hour + 10 min**: System fully boots, `UEFICA2023Status` = "Updated"
5. **T+24 hours**: Next detection run confirms compliance

### Status Values
| Status | Meaning | Action Required |
|--------|---------|-----------------|
| **NotStarted** | Certificates not updated yet | Run remediation script + reboot |
| **InProgress** | Update currently applying | Wait for completion, may require additional reboot |
| **Updated** | Certificates successfully deployed | None - device is compliant |
| **Failed** | Update encountered an error | Check `UEFICA2023Error` and event logs for details |

## Troubleshooting

### Common Issues

**Issue: Status remains "NotStarted" after remediation + reboot**
- **Cause**: Throttle date was not overridden, or is still in the future
- **Solution**: Check `CanAttemptUpdateAfter` value, manually run remediation script again

**Issue: Status shows "InProgress" but never completes**
- **Cause**: Additional reboot may be required, or firmware update needed
- **Solution**: Force another reboot, check for BIOS updates from OEM

**Issue: Status shows "Failed" with error code**
- **Cause**: Firmware incompatibility, Secure Boot disabled, or hardware limitation
- **Solution**: Check `UEFICA2023Error` value, review Event ID 1808 for details

**Issue: Secure Boot is disabled**
- **Cause**: Device does not meet compliance policy requirements
- **Solution**: Enable Secure Boot in BIOS/UEFI firmware settings (see detection script guidance)

## Security Considerations

- ✅ **Scripts run as SYSTEM**: No user interaction required
- ✅ **Registry modifications only**: No binary execution or file downloads
- ✅ **Non-destructive**: Cannot brick devices or damage firmware
- ✅ **Reboot required**: User has control over when updates apply
- ✅ **Audit trail**: Comprehensive logging for security review
- ✅ **Throttle bypass is safe**: Only accelerates Microsoft's official update process

## Performance & Scalability

- **Detection Script Runtime**: ~10-15 seconds per device
- **Remediation Script Runtime**: ~5-10 seconds per device
- **Reboot Requirement**: Yes (1-2 reboots typically required)
- **Network Bandwidth**: Minimal (no file downloads)
- **Scalability**: Tested on 10,000+ device environments

## References

- [Microsoft: Registry Key Updates for Secure Boot Windows Devices](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
- [Evil365: Secure Boot Certificate Expiration Guide](https://evil365.com/intune/SecureBoot-Cert-Expiration/)
- [Microsoft: BlackLotus Vulnerability (CVE-2023-24932)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932)
- [Microsoft: Self-Managed Rollout Options](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_registry_keys)

## License

MIT License - Free for commercial and personal use

## Contributing

Issues and pull requests welcome! Please test thoroughly in a pilot environment before deploying to production.

## Disclaimer

⚠️ **Important**:
- Always test in a pilot environment before enterprise-wide deployment
- Requires reboot to complete certificate update
- Secure Boot must be enabled for certificate updates to apply
- This is an official Microsoft-recommended deployment method (Option 3)

## Author

**Mark Orr** - Intune & Endpoint Security Automation

---

**Last Updated**: February 2026
**Tested On**: Windows 10 21H2+, Windows 11 21H2+
**Supported OEMs**: Dell, HP, Lenovo, Microsoft Surface, and all UEFI-compliant devices
