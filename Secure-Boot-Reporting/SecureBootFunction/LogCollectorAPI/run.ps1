using namespace System.Net

param($Request, $TriggerMetadata)

# Parse request body
$requestBody = $Request.Body
$azureADDeviceID = $requestBody.AzureADDeviceID
$azureADTenantID = $requestBody.AzureADTenantID
$logPayloads = $requestBody.LogPayloads

# Validate required fields
if (-not $azureADDeviceID -or -not $azureADTenantID -or -not $logPayloads) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::BadRequest
        Body = "Missing required fields: AzureADDeviceID, AzureADTenantID, LogPayloads"
    })
    return
}

# --- Device Validation via Microsoft Graph ---
try {
    $graphTokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
    if ($graphTokenResult.Token -is [securestring]) {
        $graphToken = $graphTokenResult.Token | ConvertFrom-SecureString -AsPlainText
    } else {
        $graphToken = $graphTokenResult.Token
    }
    $graphHeaders = @{
        "Authorization" = "Bearer $graphToken"
        "Content-Type"  = "application/json"
    }
    $graphUri = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$azureADDeviceID'"
    $deviceLookup = Invoke-RestMethod -Uri $graphUri -Headers $graphHeaders -Method GET

    if ($deviceLookup.value.Count -eq 0) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::Unauthorized
            Body = "Device not found in Azure AD: $azureADDeviceID"
        })
        return
    }
}
catch {
    $errorDetail = $_.Exception.Message
    if ($_.ErrorDetails.Message) { $errorDetail += " | Details: $($_.ErrorDetails.Message)" }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = "Device validation failed: $errorDetail"
    })
    return
}

# --- Send to Logs Ingestion API ---
$dceEndpoint = $env:DCE_ENDPOINT
$dcrImmutableId = $env:DCR_IMMUTABLE_ID
$monitorTokenResult = Get-AzAccessToken -ResourceUrl "https://monitor.azure.com"
if ($monitorTokenResult.Token -is [securestring]) {
    $monitorToken = $monitorTokenResult.Token | ConvertFrom-SecureString -AsPlainText
} else {
    $monitorToken = $monitorTokenResult.Token
}
$monitorHeaders = @{
    "Authorization" = "Bearer $monitorToken"
    "Content-Type"  = "application/json"
}

$responses = @()

$streamMap = @{
    "SecureBootInventory" = $env:SECUREBOOT_STREAM_NAME
}

# Handle both Hashtable and PSCustomObject deserialization
if ($logPayloads -is [hashtable] -or $logPayloads -is [System.Collections.IDictionary]) {
    $logNames = $logPayloads.Keys
} else {
    $logNames = $logPayloads.PSObject.Properties.Name
}

foreach ($logName in $logNames) {
    $streamName = $streamMap[$logName]
    if (-not $streamName) {
        $responses += @{ logname = $logName; response = "400 - Unknown log type" }
        continue
    }

    $logData = $logPayloads.$logName

    # Logs Ingestion API expects an array
    if ($logData -isnot [System.Collections.IEnumerable] -or $logData -is [string] -or $logData -is [hashtable]) {
        $logData = @($logData)
    }

    $uri = "$dceEndpoint/dataCollectionRules/$dcrImmutableId/streams/${streamName}?api-version=2023-01-01"
    $body = $logData | ConvertTo-Json -Depth 10 -AsArray

    try {
        Invoke-RestMethod -Uri $uri -Method POST -Headers $monitorHeaders -Body $body
        $responses += @{ logname = $logName; response = "200" }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $responses += @{ logname = $logName; response = "$statusCode - $($_.Exception.Message)" }
    }
}

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = ($responses | ConvertTo-Json -Depth 5)
})
