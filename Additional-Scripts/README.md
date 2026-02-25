# SecureBoot_2026_UpdateScripts_v1.0

PowerShell scripts to help enterprise IT teams prepare Windows 10/11 devices for the upcoming Microsoft UEFI Secure Boot certificate expiration in June 2026.

These scripts are designed for auditing, remediation, and inventorying Secure Boot readiness across environments managed via Microsoft Intune, MECM, or local automation tooling.

---

## Overview

Microsoft Secure Boot relies on cryptographic certificates that will begin expiring in June 2026. Without updated certificates, Windows systems will stop receiving critical boot-level updates, exposing them to malware like BlackLotus (CVE-2023-24932).

This toolkit helps ensure your systems:
- Remain trusted by Windows boot policies
- Can receive new Secure Boot CAs
- Are ready for UEFI certificate rollouts

---

## Included Scripts

| Script | Purpose |
|--------|---------|
| `Detect-SecureBootCertReadiness.ps1` | Detects Secure Boot status, diagnostic data setting, and registry opt-in for Microsoft Secure Boot updates |
| `Remediate-SecureBootConfig.ps1` | Applies required registry settings and telemetry configuration to support the 2026 certificate updates |
| `Export-SecureBootStatusReport.ps1` | Logs current certificate readiness status and firmware version to a CSV file |
| `Check-OEMFirmwareReadiness.ps1` | Captures manufacturer, model, and BIOS/UEFI firmware version for inventory or compliance tracking |
| `Get-IntuneSecureBootReport.ps1` | Retrieves Secure Boot compliance data from Intune via Microsoft Graph API and generates an HTML report |

---

## How to Use

### Detection
Run `Detect-SecureBootCertReadiness.ps1` locally or via Intune/MECM to check current status.

### Remediation
Use `Remediate-SecureBootConfig.ps1` to enable Secure Boot update readiness with correct registry and telemetry values.

### Logging
Execute `Export-SecureBootStatusReport.ps1` on multiple machines and collect outputs for estate-wide reporting.

### Firmware Audit
Use `Check-OEMFirmwareReadiness.ps1` to compare firmware versions against OEM baselines.

### Intune Report (API)
Use `Get-IntuneSecureBootReport.ps1` to pull Secure Boot status from all Intune-managed devices and generate a professional HTML report.

```powershell
# Interactive authentication (recommended for testing)
.\Get-IntuneSecureBootReport.ps1 -Interactive

# App authentication with client secret (for automation)
.\Get-IntuneSecureBootReport.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-secret"

# App authentication with certificate (most secure for automation)
.\Get-IntuneSecureBootReport.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -CertificateThumbprint "your-thumbprint"
```

#### Required Graph API Permissions
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.Read.All`

#### App Registration Setup (for automation)
1. Go to **Azure Portal** > **Azure Active Directory** > **App registrations**
2. Create a new registration
3. Add API permissions: **Microsoft Graph** > **Application permissions**
4. Add: `DeviceManagementManagedDevices.Read.All`
5. Grant admin consent
6. Create a client secret or upload a certificate

---

## Use Cases

- Prepare for the 2026 Secure Boot certificate rotation
- Validate Secure Boot configurations at scale
- Ensure CVE-2023-24932 mitigation compatibility
- Deploy via Intune Proactive Remediations or MECM scripts
- Support Windows 10 ESU and Windows 11 compliance

---

## Related Microsoft Docs

- [Secure Boot Certificate Expiration – Microsoft](https://aka.ms/securebootcerts)  
- [CVE-2023-24932 Mitigation Guidance](https://support.microsoft.com/help/5025885)  
- [Windows and Secure Boot Overview](https://learn.microsoft.com/windows/security/information-protection/secure-boot/secure-boot-overview)  

---

## Author

**Thomas Marcussen**  
Email: Thomas@ThomasMarcussen.com  
Website: [ThomasMarcussen.com](https://ThomasMarcussen.com)  
LinkedIn: [https://www.linkedin.com/in/thomasmarcussen](https://www.linkedin.com/in/thomasmarcussen)

---

## License

MIT License – use freely with attribution.
