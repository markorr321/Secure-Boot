# Secure Boot Inventory — Ready-to-Go Status

## How to Determine "Ready to Go" Devices

The Enhanced Inventory script collects 38+ data points. No single field tells you if firmware is ready — you combine multiple fields to classify each device.

---

### Ready to Go (Firmware Compatible, Update Will Proceed)

A device is **ready to go** when ALL of the following are true:

| Field | Required Value | Why |
|-------|---------------|-----|
| `SecureBootEnabled` | `True` | Prerequisite — update cannot apply without Secure Boot enabled |
| `UEFICA2023Status` | Not `"Updated"` | Device hasn't completed the update yet |
| `AvailableUpdates` | Non-null (e.g., `0x80`, `0x5944`) | Updates are staged and ready to apply |
| `Event1795Count` | `0` | No firmware rejection errors |
| `Event1802Count` | `0` | No Microsoft-known firmware block |
| `Event1803Count` | `0` | OEM has provided the required KEK |
| `MissingKEK` | `False` | Same as above — KEK is present |
| `KnownIssueId` | `null` | No KI block from Microsoft |
| `SkipReasonKnownIssue` | `null` | No skip reason blocking the update |
| `SecureBootTaskEnabled` | `True` | The scheduled task that drives the update is active |

### Query Filter

```
WHERE SecureBootEnabled = True
  AND UEFICA2023Status != 'Updated'
  AND Event1795Count = 0
  AND Event1802Count = 0
  AND MissingKEK = False
  AND SkipReasonKnownIssue IS NULL
  AND KnownIssueId IS NULL
  AND (AvailableUpdates IS NOT NULL OR Event1801Count > 0)
```

---

## Sub-Statuses

### Ready — Pending Reboot

The update is staged and will complete on the next reboot.

| Field | Value |
|-------|-------|
| `RebootPending` | `True` |
| `Event1801Count` | `> 0` (update initiated) |
| `Event1808Count` | `0` (not yet completed) |

**Action:** Schedule a device restart. No other intervention needed.

### Ready — Waiting on Cooldown Timer

Firmware is compatible but the servicing stack is throttling retries.

| Field | Value |
|-------|-------|
| `CanAttemptUpdateAfter` | A future date/time |

**Action:** Wait — the update will auto-attempt after that date. Or deploy the remediation script to bypass the throttle.

### Ready — Waiting on Policy/Opt-In

The device firmware is compatible but the update hasn't been offered yet.

| Field | Value |
|-------|-------|
| `AvailableUpdates` | `null` (no updates staged) |
| `WinCSKeyApplied` | `False` |
| All error fields | `0` / `null` / `False` |

**Action:** Enable the WinCS feature flag or set `AvailableUpdates` via GPO/remediation script.

---

## Blocked Statuses (Not Ready)

### Blocked — Firmware Error

The OEM's UEFI firmware rejected the certificate update.

| Field | Value |
|-------|-------|
| `Event1795Count` | `> 0` |
| `Event1795ErrorCode` | Error code from firmware |

**Action:** Check the OEM's support site for a BIOS/firmware update addressing Secure Boot 2023 compatibility.

### Blocked — Known Firmware Issue (Microsoft Hold)

Microsoft has identified an incompatibility and blocked the update for this hardware.

| Field | Value |
|-------|-------|
| `Event1802Count` | `> 0` |
| `KnownIssueId` | `KI_<number>` |

**Action:** The OEM must release a fixed BIOS, then Microsoft removes the block. Monitor the KI number for resolution.

### Blocked — Missing KEK

The OEM has not shipped a PK-signed KEK for the 2023 certificate. The update cannot proceed.

| Field | Value |
|-------|-------|
| `Event1803Count` | `> 0` |
| `MissingKEK` | `True` |

**Action:** This is 100% on the OEM. Contact the vendor or wait for a firmware update that includes the required KEK.

### Blocked — Secure Boot Disabled

The device cannot receive the certificate update without Secure Boot enabled.

| Field | Value |
|-------|-------|
| `SecureBootEnabled` | `False` or `null` |

**Action:** Enable Secure Boot in UEFI/BIOS settings. May require converting from Legacy BIOS to UEFI boot mode.

---

## Already Complete

| Field | Value |
|-------|-------|
| `UEFICA2023Status` | `"Updated"` |
| `SecureBootEnabled` | `True` |
| `Event1808Count` | `> 0` |

Exit code `0` — no action required.

---

## Pivoting by OEM/Model

To identify systemic firmware issues, group fleet data by:

```
GROUP BY OEMManufacturerName, OEMModelNumber, FirmwareVersion
```

This reveals whether a failure is model-specific, vendor-wide, or isolated to a single device.
