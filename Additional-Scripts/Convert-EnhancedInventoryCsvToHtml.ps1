<#
.SYNOPSIS
    Converts the Intune Proactive Remediation export CSV to an HTML report for
    the Secure Boot - UEFI-CA 2023 Inventory Collection - Enhanced script.

.DESCRIPTION
    Takes the CSV file exported from Intune Proactive Remediations
    (DeviceStatus -> Export) and parses the JSON from PreRemediationDetectionScriptOutput
    to generate a comprehensive HTML report with statistics and filtering.

    If no CSV path is provided, a file picker dialog will open.

.PARAMETER CsvPath
    Path to the CSV file exported from Intune Proactive Remediations.
    If not provided, a file picker will open.

.PARAMETER OutputPath
    Path where the HTML report will be saved. Defaults to same folder as CSV.

.EXAMPLE
    .\Convert-EnhancedInventoryCsvToHtml.ps1
    # Opens file picker dialog

.EXAMPLE
    .\Convert-EnhancedInventoryCsvToHtml.ps1 -CsvPath "C:\Downloads\RemediationResults.csv"

.EXAMPLE
    .\Convert-EnhancedInventoryCsvToHtml.ps1 -CsvPath ".\export.csv" -OutputPath "C:\Reports"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$CsvPath,

    [Parameter()]
    [string]$OutputPath
)

# If no CSV path provided, open file picker
if (-not $CsvPath) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    $filePicker = New-Object System.Windows.Forms.OpenFileDialog
    $filePicker.Title = "Select Intune Proactive Remediation Export CSV"
    $filePicker.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $filePicker.InitialDirectory = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
    
    # Bring dialog to foreground
    $topForm = New-Object System.Windows.Forms.Form
    $topForm.TopMost = $true
    $result = $filePicker.ShowDialog($topForm)
    $topForm.Dispose()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $CsvPath = $filePicker.FileName
    } else {
        Write-Host "No file selected. Exiting." -ForegroundColor Yellow
        Read-Host "Press Enter to close"
        exit 0
    }
}

# Validate path exists
if (-not (Test-Path $CsvPath -PathType Leaf)) {
    Write-Host "File not found: $CsvPath" -ForegroundColor Red
    exit 1
}

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Reading CSV file: $CsvPath" -ForegroundColor Cyan

# Import CSV
$rawData = Import-Csv -Path $CsvPath
$total = $rawData.Count

if ($total -eq 0) {
    Write-Host "No devices found in CSV file" -ForegroundColor Red
    exit 1
}

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Found $total raw records in CSV" -ForegroundColor Green

# Parse the JSON from PreRemediationDetectionScriptOutput
$devices = @()
$parseErrors = 0

foreach ($row in $rawData) {
    $jsonOutput = $row.PreRemediationDetectionScriptOutput
    
    if ([string]::IsNullOrWhiteSpace($jsonOutput)) {
        $parseErrors++
        continue
    }
    
    try {
        $parsed = $jsonOutput | ConvertFrom-Json
        
        # Create a flat object with the 15 most important fields for reporting
        $device = [PSCustomObject]@{
            # Device identification
            Hostname             = $parsed.Hostname
            
            # Secure Boot & Certificate Status (core fields)
            SecureBootEnabled    = $parsed.SecureBootEnabled
            UEFICA2023Status     = $parsed.UEFICA2023Status
            Confidence           = $parsed.Confidence
            WinCSKeyApplied      = $parsed.WinCSKeyApplied
            WinCSKeyStatus       = $parsed.WinCSKeyStatus
            RebootPending        = $parsed.RebootPending
            LatestEventId        = $parsed.LatestEventId
            
            # Hardware Info
            Manufacturer         = $parsed.OEMManufacturerName
            Model                = $parsed.OEMModelNumber
            OSVersion            = $parsed.OSVersion
            FirmwareVersion      = $parsed.FirmwareVersion
            
            # Task Status
            SecureBootTaskEnabled = $parsed.SecureBootTaskEnabled
            SecureBootTaskStatus = $parsed.SecureBootTaskStatus
            
            # Timestamp
            CollectionTime       = $parsed.CollectionTime
            
            # Raw JSON for detail view
            RawJson              = $jsonOutput
        }
        
        $devices += $device
    }
    catch {
        $parseErrors++
        Write-Verbose "Failed to parse JSON for device: $($row.DeviceName) - $_"
    }
}

$parsedCount = $devices.Count
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Successfully parsed $parsedCount devices ($parseErrors parse errors)" -ForegroundColor Green

if ($parsedCount -eq 0) {
    Write-Host "No devices with valid JSON data found" -ForegroundColor Red
    exit 1
}

# Calculate statistics
# Secure Boot Status
$sbEnabled = ($devices | Where-Object { $_.SecureBootEnabled -eq $true }).Count
$sbDisabled = ($devices | Where-Object { $_.SecureBootEnabled -eq $false }).Count
$pctSbEnabled = if ($parsedCount -gt 0) { [math]::Round(($sbEnabled / $parsedCount) * 100, 1) } else { 0 }

# UEFI CA 2023 Status
$statusNotStarted = ($devices | Where-Object { $_.UEFICA2023Status -eq "NotStarted" }).Count
$statusStaged = ($devices | Where-Object { $_.UEFICA2023Status -eq "Staged" }).Count
$statusUpdated = ($devices | Where-Object { $_.UEFICA2023Status -eq "Updated" }).Count
$pctUpdated = if ($parsedCount -gt 0) { [math]::Round(($statusUpdated / $parsedCount) * 100, 1) } else { 0 }

# WinCS Key Status
$winCSApplied = ($devices | Where-Object { $_.WinCSKeyApplied -eq $true }).Count
$winCSNotApplied = ($devices | Where-Object { $_.WinCSKeyApplied -eq $false }).Count
$pctWinCSApplied = if ($parsedCount -gt 0) { [math]::Round(($winCSApplied / $parsedCount) * 100, 1) } else { 0 }

# Reboot Pending
$rebootPending = ($devices | Where-Object { $_.RebootPending -eq $true }).Count
$pctRebootPending = if ($parsedCount -gt 0) { [math]::Round(($rebootPending / $parsedCount) * 100, 1) } else { 0 }

# Confidence Categories
$highConfidence = ($devices | Where-Object { $_.Confidence -match "High" }).Count
$underObservation = ($devices | Where-Object { $_.Confidence -match "Under Observation" }).Count

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Statistics calculated:" -ForegroundColor Cyan
Write-Host "  Secure Boot Enabled: $sbEnabled ($pctSbEnabled%)" -ForegroundColor Gray
Write-Host "  UEFI CA 2023 Updated: $statusUpdated ($pctUpdated%)" -ForegroundColor Gray
Write-Host "  WinCS Key Applied: $winCSApplied ($pctWinCSApplied%)" -ForegroundColor Gray
Write-Host "  Reboot Pending: $rebootPending ($pctRebootPending%)" -ForegroundColor Gray

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Building HTML report..." -ForegroundColor Cyan

# Build table rows
$sb = [System.Text.StringBuilder]::new()
foreach ($device in $devices) {
    # Determine row classes for key indicators
    $sbClass = if ($device.SecureBootEnabled -eq $true) { "enabled" } 
               elseif ($device.SecureBootEnabled -eq $false) { "disabled" } 
               else { "unknown" }
    
    $statusClass = if ($device.UEFICA2023Status -eq "Updated") { "enabled" }
                   elseif ($device.UEFICA2023Status -eq "Staged") { "warning" }
                   elseif ($device.UEFICA2023Status -eq "NotStarted") { "disabled" }
                   else { "unknown" }
    
    $winCSClass = if ($device.WinCSKeyApplied -eq $true) { "enabled" } 
                  elseif ($device.WinCSKeyApplied -eq $false) { "disabled" } 
                  else { "unknown" }
    
    $rebootClass = if ($device.RebootPending -eq $true) { "warning" } else { "enabled" }
    
    $confidenceClass = if ($device.Confidence -match "High") { "enabled" }
                       elseif ($device.Confidence -match "Under Observation") { "warning" }
                       else { "unknown" }
    
    $taskClass = if ($device.SecureBootTaskStatus -eq "Ready") { "enabled" } else { "unknown" }
    
    # Base64 encode JSON to avoid HTML escaping issues
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($device.RawJson)
    $base64Json = [Convert]::ToBase64String($jsonBytes)
    
    [void]$sb.AppendLine("<tr data-json='$base64Json'>")
    [void]$sb.Append("<td>$($device.Hostname)</td>")
    [void]$sb.Append("<td><span class='badge-$sbClass'>$(if($device.SecureBootEnabled){'Enabled'}else{'Disabled'})</span></td>")
    [void]$sb.Append("<td><span class='badge-$winCSClass'>$(if($device.WinCSKeyApplied){'Installed'}else{'Not Installed'})</span></td>")
    [void]$sb.Append("<td><span class='badge-$statusClass'>$($device.UEFICA2023Status)</span></td>")
    [void]$sb.Append("<td><span class='badge-$taskClass'>$(if($device.SecureBootTaskStatus -eq 'Ready'){'Yes'}else{'No'})</span></td>")
    [void]$sb.Append("<td><span class='badge-$rebootClass'>$(if($device.RebootPending){'Yes'}else{'No'})</span></td>")
    [void]$sb.Append("<td><span class='badge-$confidenceClass'>$($device.Confidence)</span></td>")
    [void]$sb.Append("<td>$($device.LatestEventId)</td>")
    [void]$sb.Append("<td>$($device.Manufacturer)</td>")
    [void]$sb.Append("<td>$($device.Model)</td>")
    [void]$sb.Append("<td>$($device.OSVersion)</td>")
    [void]$sb.Append("<td>$($device.FirmwareVersion)</td>")
    [void]$sb.Append("<td>$($device.CollectionTime)</td>")
    [void]$sb.Append("<td><button class='btn btn-detail' onclick='showDetail(this)'>View</button></td>")
    [void]$sb.AppendLine("</tr>")
}
$rows = $sb.ToString()

# Generate report path
if (-not $OutputPath) {
    $OutputPath = Split-Path -Path $CsvPath -Parent
}
$reportFile = Join-Path $OutputPath "EnhancedInventoryReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
$csvFileName = Split-Path -Path $CsvPath -Leaf

$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Secure Boot Enhanced Inventory Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f3f2f1; }
        .container { max-width: 1800px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #0078d4, #004578); color: white; padding: 24px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { font-size: 22px; }
        .header p { opacity: 0.9; margin-top: 4px; font-size: 13px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .stats-card { background: white; padding: 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stats-card h3 { font-size: 14px; color: #323130; margin-bottom: 12px; border-bottom: 1px solid #edebe9; padding-bottom: 8px; }
        .stat-row { display: flex; justify-content: space-between; margin: 8px 0; align-items: center; }
        .stat-label { color: #605e5c; font-size: 13px; }
        .stat-value { font-size: 18px; font-weight: 600; }
        .stat-value.green { color: #107c10; }
        .stat-value.red { color: #d13438; }
        .stat-value.orange { color: #ca5010; }
        .stat-value.blue { color: #0078d4; }
        .stat-value.gray { color: #8a8886; }
        .stat-bar { height: 6px; background: #edebe9; border-radius: 3px; margin-top: 4px; }
        .stat-bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
        .stat-bar-fill.green { background: #107c10; }
        .stat-bar-fill.red { background: #d13438; }
        .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
        .card-header { padding: 16px; border-bottom: 1px solid #edebe9; }
        .card-header h2 { font-size: 16px; margin: 0; }
        .filter-bar { padding: 12px 16px; background: #faf9f8; border-bottom: 1px solid #edebe9; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
        .filter-group { display: flex; align-items: center; gap: 8px; }
        .filter-group label { font-size: 13px; color: #323130; font-weight: 500; }
        .filter-group select { padding: 6px 10px; border: 1px solid #8a8886; border-radius: 4px; font-size: 13px; background: white; min-width: 140px; cursor: pointer; }
        .filter-group select:focus { outline: 2px solid #0078d4; border-color: #0078d4; }
        input[type=text] { padding: 8px 12px; border: 1px solid #8a8886; border-radius: 4px; width: 220px; font-size: 13px; }
        input[type=text]:focus { outline: 2px solid #0078d4; border-color: #0078d4; }
        .btn { padding: 6px 12px; border: 1px solid #edebe9; border-radius: 4px; background: white; cursor: pointer; font-size: 12px; }
        .btn:hover { border-color: #0078d4; background: #f3f2f1; }
        .btn-export { background: #0078d4; color: white; border: none; font-weight: 500; padding: 8px 16px; font-size: 13px; }
        .btn-export:hover { background: #106ebe; }
        .btn-detail { background: #f3f2f1; font-size: 11px; padding: 4px 8px; }
        .table-wrap { overflow-x: auto; max-height: 60vh; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th { background: #faf9f8; padding: 10px 12px; text-align: left; font-weight: 600; cursor: pointer; white-space: nowrap; border-bottom: 2px solid #edebe9; position: sticky; top: 0; z-index: 1; }
        th:hover { background: #f3f2f1; }
        th::after { content: ' ↕'; opacity: 0.3; font-size: 10px; }
        td { padding: 8px 12px; border-bottom: 1px solid #edebe9; white-space: nowrap; }
        tr:hover { background: #faf9f8; }
        .enabled { color: #107c10; }
        .disabled { color: #d13438; }
        .warning { color: #ca5010; }
        .unknown { color: #605e5c; }
        .badge-enabled, .badge-disabled, .badge-warning, .badge-unknown { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 500; }
        .badge-enabled { background: #dff6dd; color: #107c10; }
        .badge-disabled { background: #fde7e9; color: #d13438; }
        .badge-warning { background: #fff4ce; color: #ca5010; }
        .badge-unknown { background: #f3f2f1; color: #605e5c; }
        .footer { text-align: center; padding: 16px; color: #605e5c; font-size: 12px; }
        .count { background: #e1dfdd; padding: 6px 12px; border-radius: 4px; font-size: 13px; color: #323130; font-weight: 500; }
        /* Modal styles */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); }
        .modal-content { background: white; margin: 5% auto; width: 90%; max-width: 1000px; border-radius: 8px; max-height: 85vh; display: flex; flex-direction: column; }
        .modal-header { padding: 16px 20px; border-bottom: 1px solid #edebe9; display: flex; justify-content: space-between; align-items: center; }
        .modal-header h3 { font-size: 16px; }
        .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: #605e5c; }
        .modal-close:hover { color: #d13438; }
        .modal-body { padding: 20px; overflow-y: auto; flex: 1; }
        .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .detail-section { border: 1px solid #edebe9; border-radius: 6px; padding: 16px; }
        .detail-section h4 { font-size: 14px; color: #0078d4; margin-bottom: 12px; border-bottom: 1px solid #edebe9; padding-bottom: 8px; }
        .detail-row { display: flex; justify-content: space-between; margin: 6px 0; font-size: 13px; }
        .detail-row .label { color: #605e5c; }
        .detail-row .value { font-weight: 500; color: #323130; }
        .detail-row .value.true { color: #107c10; }
        .detail-row .value.false { color: #d13438; }
        .json-section { margin-top: 16px; }
        .json-section h4 { font-size: 13px; color: #605e5c; margin-bottom: 8px; }
        .json-code { background: #f3f2f1; padding: 12px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 11px; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Secure Boot - UEFI-CA 2023 Enhanced Inventory Report</h1>
        <p>Generated: $reportDate | Source: $csvFileName | Devices: $parsedCount ($parseErrors parse errors)</p>
    </div>
    
    <div class="stats-grid">
        <div class="stats-card">
            <h3>Secure Boot Status</h3>
            <div class="stat-row">
                <span class="stat-label">Enabled</span>
                <span class="stat-value green">$sbEnabled <small>($pctSbEnabled%)</small></span>
            </div>
            <div class="stat-bar"><div class="stat-bar-fill green" style="width: $pctSbEnabled%"></div></div>
            <div class="stat-row">
                <span class="stat-label">Disabled</span>
                <span class="stat-value red">$sbDisabled</span>
            </div>
        </div>
        
        <div class="stats-card">
            <h3>Update Progress</h3>
            <div class="stat-row">
                <span class="stat-label">Updated</span>
                <span class="stat-value green">$statusUpdated <small>($pctUpdated%)</small></span>
            </div>
            <div class="stat-bar"><div class="stat-bar-fill green" style="width: $pctUpdated%"></div></div>
            <div class="stat-row">
                <span class="stat-label">In Progress</span>
                <span class="stat-value orange">$statusStaged</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Not Started</span>
                <span class="stat-value red">$statusNotStarted</span>
            </div>
        </div>
        
        <div class="stats-card">
            <h3>2023 Certificate Status</h3>
            <div class="stat-row">
                <span class="stat-label">Installed</span>
                <span class="stat-value green">$winCSApplied <small>($pctWinCSApplied%)</small></span>
            </div>
            <div class="stat-bar"><div class="stat-bar-fill green" style="width: $pctWinCSApplied%"></div></div>
            <div class="stat-row">
                <span class="stat-label">Not Installed</span>
                <span class="stat-value red">$winCSNotApplied</span>
            </div>
        </div>
        
        <div class="stats-card">
            <h3>Rollout Status</h3>
            <div class="stat-row">
                <span class="stat-label">Ready for Update</span>
                <span class="stat-value green">$highConfidence</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Under Observation</span>
                <span class="stat-value orange">$underObservation</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Reboot Needed</span>
                <span class="stat-value orange">$rebootPending <small>($pctRebootPending%)</small></span>
            </div>
        </div>
    </div>
    
    <div class="card">
        <div class="card-header">
            <h2>Device Details</h2>
        </div>
        <div class="filter-bar">
            <input type="text" id="search" placeholder="Search all columns...">
            
            <div class="filter-group">
                <label>Secure Boot:</label>
                <select id="sbFilter">
                    <option value="all">All</option>
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                </select>
            </div>

            <div class="filter-group">
                <label>2023 Cert:</label>
                <select id="wincsFilter">
                    <option value="all">All</option>
                    <option value="installed">Installed</option>
                    <option value="not installed">Not Installed</option>
                </select>
            </div>

            <div class="filter-group">
                <label>Update Status:</label>
                <select id="statusFilter">
                    <option value="all">All</option>
                    <option value="updated">Updated</option>
                    <option value="staged">In Progress</option>
                    <option value="notstarted">Not Started</option>
                </select>
            </div>

            <div class="filter-group">
                <label>Reboot:</label>
                <select id="rebootFilter">
                    <option value="all">All</option>
                    <option value="yes">Needed</option>
                    <option value="no">Not Needed</option>
                </select>
            </div>
            
            <button class="btn btn-export" onclick="exportCSV()">Export CSV</button>
            <span class="count" id="count">$parsedCount devices</span>
        </div>
        <div class="table-wrap">
            <table id="tbl">
                <thead>
                    <tr>
                        <th onclick="sort(this)">Device</th>
                        <th onclick="sort(this)">Secure Boot</th>
                        <th onclick="sort(this)">2023 Cert</th>
                        <th onclick="sort(this)">Update Status</th>
                        <th onclick="sort(this)">Task Ready</th>
                        <th onclick="sort(this)">Reboot Needed</th>
                        <th onclick="sort(this)">Rollout Status</th>
                        <th onclick="sort(this)">Last Event</th>
                        <th onclick="sort(this)">Manufacturer</th>
                        <th onclick="sort(this)">Model</th>
                        <th onclick="sort(this)">OS Version</th>
                        <th onclick="sort(this)">BIOS Version</th>
                        <th onclick="sort(this)">Collected</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>$rows</tbody>
            </table>
        </div>
    </div>
    <div class="footer">Source: Intune Proactive Remediations Export | Secure Boot - UEFI-CA 2023 Inventory Collection - Enhanced</div>
</div>

<!-- Detail Modal -->
<div id="detailModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="modalTitle">Device Details</h3>
            <button class="modal-close" onclick="closeModal()">&times;</button>
        </div>
        <div class="modal-body" id="modalBody">
        </div>
    </div>
</div>

<script>
// Column indices (0-based) - Device | Secure Boot | 2023 Cert | Update Status | Task Ready | Reboot | Rollout Status | ...
const COL_SECURE_BOOT = 1;
const COL_WINCS_KEY = 2;
const COL_UEFI_STATUS = 3;
const COL_REBOOT = 5;

// Event listeners
document.getElementById('search').addEventListener('input', filter);
document.getElementById('sbFilter').addEventListener('change', filter);
document.getElementById('statusFilter').addEventListener('change', filter);
document.getElementById('wincsFilter').addEventListener('change', filter);
document.getElementById('rebootFilter').addEventListener('change', filter);

function filter() {
    const searchText = document.getElementById('search').value.toLowerCase();
    const sbFilter = document.getElementById('sbFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const wincsFilter = document.getElementById('wincsFilter').value;
    const rebootFilter = document.getElementById('rebootFilter').value;
    let visible = 0;
    
    const rows = document.querySelectorAll('#tbl tbody tr');
    rows.forEach(row => {
        const rowText = row.textContent.toLowerCase();
        
        // Secure Boot filter
        let matchSb = true;
        if (sbFilter !== 'all') {
            const val = row.cells[COL_SECURE_BOOT]?.textContent?.trim()?.toLowerCase();
            if (sbFilter === 'true') matchSb = val === 'enabled';
            if (sbFilter === 'false') matchSb = val === 'disabled';
        }
        
        // UEFI CA Status filter
        let matchStatus = true;
        if (statusFilter !== 'all') {
            const val = row.cells[COL_UEFI_STATUS]?.textContent?.trim()?.toLowerCase();
            matchStatus = val === statusFilter;
        }
        
        // 2023 Cert filter
        let matchWincs = true;
        if (wincsFilter !== 'all') {
            const val = row.cells[COL_WINCS_KEY]?.textContent?.trim()?.toLowerCase();
            matchWincs = val === wincsFilter;
        }
        
        // Reboot filter
        let matchReboot = true;
        if (rebootFilter !== 'all') {
            const val = row.cells[COL_REBOOT]?.textContent?.trim()?.toLowerCase();
            matchReboot = val === rebootFilter;
        }
        
        // Search filter
        const matchSearch = searchText === '' || rowText.includes(searchText);
        
        const show = matchSearch && matchSb && matchStatus && matchWincs && matchReboot;
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });
    
    document.getElementById('count').textContent = visible + ' devices';
}

let sortDir = {};
function sort(th) {
    const idx = Array.from(th.parentNode.children).indexOf(th);
    const tb = document.querySelector('#tbl tbody');
    const rows = Array.from(tb.rows);
    sortDir[idx] = !sortDir[idx];
    rows.sort((a, b) => {
        const aVal = a.cells[idx]?.textContent?.trim() || '';
        const bVal = b.cells[idx]?.textContent?.trim() || '';
        const aNum = parseFloat(aVal), bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return sortDir[idx] ? aNum - bNum : bNum - aNum;
        }
        return sortDir[idx] ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    rows.forEach(r => tb.appendChild(r));
}

function exportCSV() {
    let csv = [];
    document.querySelectorAll('#tbl tr').forEach(r => {
        if (r.style.display !== 'none') {
            const cells = Array.from(r.querySelectorAll('th,td'));
            // Skip the last column (Details button)
            csv.push(cells.slice(0, -1).map(c => '"' + c.textContent.trim().replace(/"/g, '""') + '"').join(','));
        }
    });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv.join('\n')], {type: 'text/csv'}));
    a.download = 'EnhancedInventory_Filtered_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
}

function showDetail(btn) {
    const row = btn.closest('tr');
    const base64Json = row.getAttribute('data-json');
    let data;
    try {
        // Decode Base64 to JSON string, then parse
        const jsonStr = atob(base64Json);
        data = JSON.parse(jsonStr);
    } catch (e) {
        alert('Failed to parse device data: ' + e.message);
        return;
    }
    
    document.getElementById('modalTitle').textContent = data.Hostname || 'Device Details';
    
    const fv = (val) => {
        if (val === true) return '<span class="value true">True</span>';
        if (val === false) return '<span class="value false">False</span>';
        if (val === null || val === undefined || val === '') return '<span class="value">N/A</span>';
        return '<span class="value">' + val + '</span>';
    };
    
    // Format timestamp to PST
    const formatPST = (isoStr) => {
        if (!isoStr) return '<span class="value">N/A</span>';
        try {
            const date = new Date(isoStr);
            const pst = date.toLocaleString('en-US', { 
                timeZone: 'America/Los_Angeles',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
            return '<span class="value">' + pst + ' PST</span>';
        } catch (e) {
            return '<span class="value">' + isoStr + '</span>';
        }
    };
    
    // Format confidence to friendly text
    const formatConfidence = (val) => {
        if (!val) return '<span class="value">N/A</span>';
        if (val.includes('High')) return '<span class="value true">Ready for Update</span>';
        if (val.includes('Under Observation')) return '<span class="value" style="color:#ca5010">Under Observation</span>';
        return '<span class="value">' + val + '</span>';
    };
    
    // Format bucket ID (truncate with tooltip)
    const formatBucketId = (val) => {
        if (!val) return '<span class="value">N/A</span>';
        const short = val.substring(0, 12) + '...';
        return '<span class="value" title="' + val + '" style="cursor:help">' + short + '</span>';
    };
    
    let html = '<div class="detail-grid">';
    
    // Device Information
    html += '<div class="detail-section"><h4>Device Information</h4>';
    html += '<div class="detail-row"><span class="label">Hostname</span>' + fv(data.Hostname) + '</div>';
    html += '<div class="detail-row"><span class="label">Manufacturer</span>' + fv(data.OEMManufacturerName) + '</div>';
    html += '<div class="detail-row"><span class="label">Model</span>' + fv(data.OEMModelNumber) + '</div>';
    html += '<div class="detail-row"><span class="label">Model Family</span>' + fv(data.OEMModelSystemFamily) + '</div>';
    html += '<div class="detail-row"><span class="label">OS Version</span>' + fv(data.OSVersion) + '</div>';
    html += '<div class="detail-row"><span class="label">OS Architecture</span>' + fv(data.OSArchitecture) + '</div>';
    html += '<div class="detail-row"><span class="label">Firmware Version</span>' + fv(data.FirmwareVersion) + '</div>';
    html += '<div class="detail-row"><span class="label">Firmware Release</span>' + fv(data.FirmwareReleaseDate) + '</div>';
    html += '</div>';
    
    // Secure Boot & Certificate Status
    html += '<div class="detail-section"><h4>Secure Boot &amp; Certificate Status</h4>';
    html += '<div class="detail-row"><span class="label">Secure Boot Enabled</span>' + fv(data.SecureBootEnabled) + '</div>';
    html += '<div class="detail-row"><span class="label">UEFI CA 2023 Status</span>' + fv(data.UEFICA2023Status) + '</div>';
    html += '<div class="detail-row"><span class="label">UEFI CA 2023 Error</span>' + fv(data.UEFICA2023Error) + '</div>';
    html += '<div class="detail-row"><span class="label">Rollout Status</span>' + formatConfidence(data.Confidence) + '</div>';
    html += '<div class="detail-row"><span class="label">Bucket ID</span>' + formatBucketId(data.BucketId) + '</div>';
    html += '<div class="detail-row"><span class="label">Eligible for Update After</span>' + formatPST(data.CanAttemptUpdateAfter) + '</div>';
    html += '</div>';
    
    // WinCS Key Status
    html += '<div class="detail-section"><h4>2023 Certificate Status</h4>';
    html += '<div class="detail-row"><span class="label">Certificate Installed</span>' + fv(data.WinCSKeyApplied) + '</div>';
    html += '<div class="detail-row"><span class="label">Installation Status</span>' + fv(data.WinCSKeyStatus) + '</div>';
    html += '<div class="detail-row"><span class="label">Missing KEK</span>' + fv(data.MissingKEK) + '</div>';
    html += '<div class="detail-row"><span class="label">Available Updates</span>' + fv(data.AvailableUpdates) + '</div>';
    html += '</div>';
    
    // Scheduled Task
    html += '<div class="detail-section"><h4>Scheduled Task</h4>';
    html += '<div class="detail-row"><span class="label">Task Enabled</span>' + fv(data.SecureBootTaskEnabled) + '</div>';
    html += '<div class="detail-row"><span class="label">Task Status</span>' + fv(data.SecureBootTaskStatus) + '</div>';
    html += '<div class="detail-row"><span class="label">Reboot Pending</span>' + fv(data.RebootPending) + '</div>';
    html += '<div class="detail-row"><span class="label">Last Boot Time</span>' + formatPST(data.LastBootTime) + '</div>';
    html += '</div>';
    
    // Event Log Counts
    html += '<div class="detail-section"><h4>Event Log Counts</h4>';
    html += '<div class="detail-row"><span class="label">Latest Event ID</span>' + fv(data.LatestEventId) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1795 (Staging)</span>' + fv(data.Event1795Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1796 (Apply Ready)</span>' + fv(data.Event1796Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1800 (Error)</span>' + fv(data.Event1800Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1801 (Update Reboot)</span>' + fv(data.Event1801Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1802 (Success)</span>' + fv(data.Event1802Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1803 (Incompatible)</span>' + fv(data.Event1803Count) + '</div>';
    html += '<div class="detail-row"><span class="label">Event 1808 (Audit)</span>' + fv(data.Event1808Count) + '</div>';
    html += '</div>';
    
    // Timestamps
    html += '<div class="detail-section"><h4>Timestamps</h4>';
    html += '<div class="detail-row"><span class="label">Collection Time</span>' + formatPST(data.CollectionTime) + '</div>';
    html += '</div>';
    
    html += '</div>'; // close detail-grid
    
    // Raw JSON section
    html += '<div class="json-section"><h4>Raw JSON Data (All 41 Fields)</h4>';
    html += '<div class="json-code">' + JSON.stringify(data, null, 2) + '</div></div>';
    
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('detailModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('detailModal').style.display = 'none';
}

// Close modal on outside click
window.onclick = function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) {
        modal.style.display = 'none';
    }
}

// Close modal on Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeModal();
    }
});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Report saved: $reportFile" -ForegroundColor Green

Start-Process $reportFile
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Done! Report opened in browser." -ForegroundColor Green

# Keep window open if run from Explorer (double-click)
if (-not $env:WT_SESSION -and -not $env:TERM_PROGRAM) {
    Write-Host ""
    Read-Host "Press Enter to close"
}
