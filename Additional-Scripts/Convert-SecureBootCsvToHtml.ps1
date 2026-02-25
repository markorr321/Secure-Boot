<#
.SYNOPSIS
    Converts the Intune Secure Boot Report CSV export to an HTML report.

.DESCRIPTION
    Takes the CSV file exported from the Intune Secure Boot Report
    (https://intune.microsoft.com/#view/Microsoft_EMM_ModernWorkplace/SecureBootReport.ReactView)
    and generates a professional HTML report with statistics and filtering.

    If no CSV path is provided, a file picker dialog will open.

.PARAMETER CsvPath
    Path to the CSV file exported from Intune. If not provided, a file picker will open.

.PARAMETER OutputPath
    Path where the HTML report will be saved. Defaults to same folder as CSV.

.EXAMPLE
    .\Convert-SecureBootCsvToHtml.ps1
    # Opens file picker dialog

.EXAMPLE
    .\Convert-SecureBootCsvToHtml.ps1 -CsvPath "C:\Downloads\SecureBootReport.csv"

.EXAMPLE
    .\Convert-SecureBootCsvToHtml.ps1 -CsvPath ".\export.csv" -OutputPath "C:\Reports"
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
    
    $filePicker = New-Object System.Windows.Forms.OpenFileDialog
    $filePicker.Title = "Select Intune Secure Boot Report CSV"
    $filePicker.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $filePicker.InitialDirectory = [System.IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'), 'Downloads')
    
    $result = $filePicker.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $CsvPath = $filePicker.FileName
    } else {
        Write-Host "No file selected. Exiting." -ForegroundColor Yellow
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
$devices = Import-Csv -Path $CsvPath
$total = $devices.Count

if ($total -eq 0) {
    Write-Host "No devices found in CSV file" -ForegroundColor Red
    exit 1
}

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Found $total devices" -ForegroundColor Green

# Detect column names (Intune exports may vary)
$columns = $devices[0].PSObject.Properties.Name
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Columns detected: $($columns -join ', ')" -ForegroundColor Gray

# Find the Secure Boot status column
$secureBootCol = $columns | Where-Object { $_ -match "Secure\s*Boot" } | Select-Object -First 1
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Using Secure Boot column: $secureBootCol" -ForegroundColor Yellow

# Find the Certificate status column
$certStatusCol = $columns | Where-Object { $_ -match "Certificate\s*status" } | Select-Object -First 1
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Using Certificate Status column: $certStatusCol" -ForegroundColor Yellow

# Calculate Secure Boot statistics
$secureBootYes = ($devices | Where-Object { $_.$secureBootCol -match "^(Enabled|True|Yes|On|1)$" }).Count
$secureBootNo = ($devices | Where-Object { $_.$secureBootCol -match "^(Disabled|False|No|Off|0)$" }).Count
$secureBootOther = $total - $secureBootYes - $secureBootNo
$pctSecureBootYes = if ($total -gt 0) { [math]::Round(($secureBootYes / $total) * 100, 1) } else { 0 }
$pctSecureBootNo = if ($total -gt 0) { [math]::Round(($secureBootNo / $total) * 100, 1) } else { 0 }

# Calculate Certificate status statistics
$certUpToDate = 0
$certNotUpToDate = 0
$certOther = 0

if ($certStatusCol) {
    # Use exact match to avoid "Up to date" matching "Not up to date"
    $certNotUpToDate = ($devices | Where-Object { $_.$certStatusCol -eq "Not up to date" }).Count
    $certUpToDate = ($devices | Where-Object { $_.$certStatusCol -eq "Up to date" }).Count
    $certOther = $total - $certUpToDate - $certNotUpToDate
}

$pctCertUpToDate = if ($total -gt 0) { [math]::Round(($certUpToDate / $total) * 100, 1) } else { 0 }
$pctCertNotUpToDate = if ($total -gt 0) { [math]::Round(($certNotUpToDate / $total) * 100, 1) } else { 0 }

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secure Boot: Yes=$secureBootYes ($pctSecureBootYes%), No=$secureBootNo ($pctSecureBootNo%)" -ForegroundColor Cyan
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Certificate: Up to date=$certUpToDate ($pctCertUpToDate%), Not up to date=$certNotUpToDate ($pctCertNotUpToDate%)" -ForegroundColor Cyan

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Building HTML report..." -ForegroundColor Cyan

# Build table rows
$sb = [System.Text.StringBuilder]::new()
foreach ($device in $devices) {
    $sbStatus = $device.$secureBootCol
    $sbClass = if ($sbStatus -match "Yes|Enabled|True|On|1") { "enabled" } 
               elseif ($sbStatus -match "No|Disabled|False|Off|0") { "disabled" } 
               else { "unknown" }
    
    $certStatus = if ($certStatusCol) { $device.$certStatusCol } else { "" }
    # Check "Not up to date" FIRST (before "Up to date" since it contains both)
    $certClass = if ($certStatus -match "Not up to date") { "disabled" } 
                 elseif ($certStatus -match "Up to date") { "enabled" } 
                 else { "unknown" }
    
    [void]$sb.Append("<tr>")
    foreach ($col in $columns) {
        $value = $device.$col
        if ($col -eq $secureBootCol) {
            [void]$sb.Append("<td class='status-$sbClass'><span class='badge-$sbClass'>$value</span></td>")
        } elseif ($col -eq $certStatusCol) {
            [void]$sb.Append("<td class='status-$certClass'><span class='badge-$certClass'>$value</span></td>")
        } else {
            [void]$sb.Append("<td>$value</td>")
        }
    }
    [void]$sb.AppendLine("</tr>")
}
$rows = $sb.ToString()

# Build header row
$headerRow = ($columns | ForEach-Object { "<th onclick='sort(this)'>$_</th>" }) -join ""

# Generate report path
if (-not $OutputPath) {
    $OutputPath = Split-Path -Path $CsvPath -Parent
}
$reportFile = Join-Path $OutputPath "SecureBootReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
$csvFileName = Split-Path -Path $CsvPath -Leaf

$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Secure Boot Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f3f2f1; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #0078d4, #004578); color: white; padding: 24px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { font-size: 22px; }
        .header p { opacity: 0.9; margin-top: 4px; font-size: 13px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
        .stat { background: white; padding: 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-val { font-size: 28px; font-weight: 600; }
        .stat-lbl { color: #605e5c; font-size: 13px; }
        .stat.total .stat-val { color: #0078d4; }
        .stat.enabled .stat-val { color: #107c10; }
        .stat.disabled .stat-val { color: #d13438; }
        .stat.other .stat-val { color: #8a8886; }
        .stat.pct .stat-val { color: #107c10; }
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
        .btn { padding: 8px 16px; border: 1px solid #edebe9; border-radius: 4px; background: white; cursor: pointer; font-size: 13px; }
        .btn:hover { border-color: #0078d4; background: #f3f2f1; }
        .btn-export { background: #0078d4; color: white; border: none; font-weight: 500; }
        .btn-export:hover { background: #106ebe; }
        .table-wrap { overflow-x: auto; max-height: 65vh; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #faf9f8; padding: 10px 12px; text-align: left; font-weight: 600; cursor: pointer; white-space: nowrap; border-bottom: 2px solid #edebe9; position: sticky; top: 0; z-index: 1; }
        th:hover { background: #f3f2f1; }
        th::after { content: ' ↕'; opacity: 0.3; font-size: 10px; }
        td { padding: 8px 12px; border-bottom: 1px solid #edebe9; white-space: nowrap; }
        tr:hover { background: #faf9f8; }
        .status-enabled { color: #107c10; font-weight: 500; }
        .status-disabled { color: #d13438; font-weight: 500; }
        .status-unknown { color: #605e5c; }
        .badge-enabled, .badge-disabled, .badge-unknown { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 500; }
        .badge-enabled { background: #dff6dd; color: #107c10; }
        .badge-disabled { background: #fde7e9; color: #d13438; }
        .badge-unknown { background: #f3f2f1; color: #605e5c; }
        .footer { text-align: center; padding: 16px; color: #605e5c; font-size: 12px; }
        .count { background: #e1dfdd; padding: 6px 12px; border-radius: 4px; font-size: 13px; color: #323130; font-weight: 500; }
        .stats-section { margin-bottom: 20px; }
        .stats-section h3 { font-size: 14px; color: #323130; margin-bottom: 10px; padding-left: 4px; }
        .stat-pct { font-size: 13px; color: #605e5c; margin-top: 2px; }
        .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Secure Boot &amp; Certificate Status Report</h1>
        <p>Generated: $reportDate | Source: $csvFileName</p>
    </div>
    
    <div class="stats-section">
        <h3>Secure Boot Status</h3>
        <div class="stats-row">
            <div class="stat total"><div class="stat-val">$total</div><div class="stat-lbl">Total Devices</div></div>
            <div class="stat enabled"><div class="stat-val">$secureBootYes</div><div class="stat-lbl">Secure Boot Enabled</div><div class="stat-pct">$pctSecureBootYes%</div></div>
            <div class="stat disabled"><div class="stat-val">$secureBootNo</div><div class="stat-lbl">Secure Boot Disabled</div><div class="stat-pct">$pctSecureBootNo%</div></div>
        </div>
    </div>
    
    <div class="stats-section">
        <h3>Certificate Status</h3>
        <div class="stats-row">
            <div class="stat enabled"><div class="stat-val">$certUpToDate</div><div class="stat-lbl">Up to Date</div><div class="stat-pct">$pctCertUpToDate%</div></div>
            <div class="stat disabled"><div class="stat-val">$certNotUpToDate</div><div class="stat-lbl">Not Up to Date</div><div class="stat-pct">$pctCertNotUpToDate%</div></div>
            <div class="stat other"><div class="stat-val">$certOther</div><div class="stat-lbl">Unknown</div></div>
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
                    <option value="yes">Yes</option>
                    <option value="no">No</option>
                </select>
            </div>
            
            <div class="filter-group">
                <label>Certificate:</label>
                <select id="certFilter">
                    <option value="all">All</option>
                    <option value="uptodate">Up to Date</option>
                    <option value="notuptodate">Not Up to Date</option>
                </select>
            </div>
            
            <button class="btn btn-export" onclick="exportCSV()">Export Filtered CSV</button>
            <span class="count" id="count">$total devices</span>
        </div>
        <div class="table-wrap">
            <table id="tbl">
                <thead><tr>$headerRow</tr></thead>
                <tbody>$rows</tbody>
            </table>
        </div>
    </div>
    <div class="footer">Source: Intune Secure Boot Report CSV Export</div>
</div>
<script>
// Find column indices based on actual header text
const headers = Array.from(document.querySelectorAll('#tbl thead th'));
console.log('Headers:', headers.map(h => h.textContent));

const sbColIndex = headers.findIndex(th => th.textContent.toLowerCase().includes('secure boot'));
const certColIndex = headers.findIndex(th => th.textContent.toLowerCase().includes('certificate'));
console.log('Secure Boot col:', sbColIndex, 'Certificate col:', certColIndex);

// Event listeners
document.getElementById('search').addEventListener('input', filter);
document.getElementById('sbFilter').addEventListener('change', filter);
document.getElementById('certFilter').addEventListener('change', filter);

function filter() {
    const searchText = document.getElementById('search').value.toLowerCase();
    const sbFilter = document.getElementById('sbFilter').value;
    const certFilter = document.getElementById('certFilter').value;
    let visible = 0;
    
    const rows = document.querySelectorAll('#tbl tbody tr');
    rows.forEach(row => {
        const rowText = row.textContent.toLowerCase();
        
        // Secure Boot filter
        let matchSb = true;
        if (sbColIndex >= 0 && sbFilter !== 'all') {
            const sbVal = row.cells[sbColIndex]?.textContent?.toLowerCase()?.trim() || '';
            if (sbFilter === 'yes') matchSb = sbVal === 'yes';
            if (sbFilter === 'no') matchSb = sbVal === 'no';
        }
        
        // Certificate filter  
        let matchCert = true;
        if (certColIndex >= 0 && certFilter !== 'all') {
            const certVal = row.cells[certColIndex]?.textContent?.toLowerCase()?.trim() || '';
            if (certFilter === 'uptodate') matchCert = certVal === 'up to date';
            if (certFilter === 'notuptodate') matchCert = certVal === 'not up to date';
        }
        
        // Search filter
        const matchSearch = searchText === '' || rowText.includes(searchText);
        
        const show = matchSearch && matchSb && matchCert;
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
            csv.push(Array.from(r.querySelectorAll('th,td')).map(c => '"' + c.textContent.trim().replace(/"/g, '""') + '"').join(','));
        }
    });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv.join('\n')], {type: 'text/csv'}));
    a.download = 'SecureBootReport_Filtered.csv';
    a.click();
}
</script>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Report saved: $reportFile" -ForegroundColor Green

Start-Process $reportFile
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Done!" -ForegroundColor Green
