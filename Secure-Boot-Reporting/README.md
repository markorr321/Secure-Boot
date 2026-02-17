# Secure Boot Compliance Reporting

Fleet-wide Secure Boot status and UEFI CA 2023 certificate compliance monitoring via Azure Log Analytics.

Collects 28 data points per device including Secure Boot enabled state, certificate update status (KB5072718), device attributes, firmware info, and event log data.

## Architecture

```
Windows Device (Intune Enrolled)
    | POST JSON via Proactive Remediation
Azure Function (PowerShell, Managed Identity)
    |-- Validates device in Azure AD (Microsoft Graph)
    |-- Sends data to Logs Ingestion API
            |
    Data Collection Endpoint --> Data Collection Rule
            |
    Log Analytics Workspace
        |-- SecureBootInventory_CL (custom table)
            |
    Azure Monitor Workbook (Secure Boot Compliance Dashboard)
```

## Deployment

### Option A: Terraform (Recommended)

```powershell
cd terraform
terraform init
terraform plan -var="subscription_id=YOUR-SUB-ID"
terraform apply -var="subscription_id=YOUR-SUB-ID"
```

Update `Invoke-SecureBootCollection.ps1` with the `function_url` output.

### Option B: Azure CLI (Step-by-Step)

#### Step 1: Set Variables
```powershell
$SUB = "YOUR-SUBSCRIPTION-ID"
$RG = "rg-secure-boot-reporting"
$LOC = "centralus"
$LAW = "law-secure-boot-reporting"
$DCE = "dce-secureboot"
$DCR = "dcr-secureboot"
```

#### Step 2: Create Resource Group
```powershell
az group create --name $RG --location $LOC
```

#### Step 3: Create Log Analytics Workspace
```powershell
az monitor log-analytics workspace create --resource-group $RG --workspace-name $LAW --location $LOC --retention-time 30
```

#### Step 4: Create Custom Table
```powershell
$LAW_ID = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAW --query id -o tsv

az rest --method PUT --url "$LAW_ID/tables/SecureBootInventory_CL?api-version=2022-10-01" --headers "Content-Type=application/json" --body "@table-schema.json"
```

Create `table-schema.json` with the SecureBootInventory_CL schema from `dcr.json` stream declarations, using `dateTime` for TimeGenerated type.

#### Step 5: Create Data Collection Endpoint
```powershell
az monitor data-collection endpoint create --name $DCE --resource-group $RG --location $LOC --public-network-access Enabled
```

#### Step 6: Create Data Collection Rule
```powershell
# Update dcr.json with actual DCE and workspace resource IDs
az monitor data-collection rule create --name $DCR --resource-group $RG --location $LOC --rule-file dcr.json
```

#### Step 7: Create Storage Account
```powershell
$STORAGE = "stsecboot$(openssl rand -hex 4)"
az storage account create --name $STORAGE --resource-group $RG --location $LOC --sku Standard_LRS
```

#### Step 8: Create Function App
```powershell
az functionapp create --name "func-secure-boot-SUFFIX" --resource-group $RG --storage-account $STORAGE --consumption-plan-location $LOC --runtime powershell --runtime-version 7.4 --functions-version 4 --os-type Windows --assign-identity [system]
```

#### Step 9: Configure App Settings
```powershell
$DCE_ENDPOINT = az monitor data-collection endpoint show --name $DCE --resource-group $RG --query logsIngestion.endpoint -o tsv
$DCR_IMMUTABLE = az monitor data-collection rule show --name $DCR --resource-group $RG --query immutableId -o tsv

az functionapp config appsettings set --name "FUNC-NAME" --resource-group $RG --settings "DCE_ENDPOINT=$DCE_ENDPOINT" "DCR_IMMUTABLE_ID=$DCR_IMMUTABLE" "SECUREBOOT_STREAM_NAME=Custom-SecureBootInventory_CL"
```

#### Step 10: Deploy Function Code
```powershell
cd SecureBootFunction
Compress-Archive -Path * -DestinationPath ../function-deploy.zip -Force
az functionapp deployment source config-zip --resource-group $RG --name "FUNC-NAME" --src ../function-deploy.zip
```

#### Step 11: Assign Monitoring Metrics Publisher Role
```powershell
$FUNC_PRINCIPAL = az functionapp identity show --name "FUNC-NAME" --resource-group $RG --query principalId -o tsv
$DCR_ID = az monitor data-collection rule show --name $DCR --resource-group $RG --query id -o tsv

az role assignment create --assignee $FUNC_PRINCIPAL --role "Monitoring Metrics Publisher" --scope $DCR_ID
```

#### Step 12: Grant Graph API Device.Read.All Permission
```powershell
$GRAPH_SP = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].id" -o tsv
$ROLE_ID = az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP/appRoles" --query "value[?value=='Device.Read.All'].id" -o json

# Create role-body.json with principalId, resourceId, appRoleId
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$FUNC_PRINCIPAL/appRoleAssignments" --headers "Content-Type=application/json" --body "@role-body.json"
```

#### Step 13: Deploy Workbook
Deploy `Reporting/SecureBoot/Secure_Boot_Compliance.workbook` via Azure Portal or REST API.

#### Step 14: Update Client Script
Set `$AzureFunctionURL` in `Invoke-SecureBootCollection.ps1` to your function URL.

## Testing

1. Run the client script as Administrator in Windows PowerShell 5.1:
   ```powershell
   .\Invoke-SecureBootCollection.ps1
   ```
   Expected output: `CollectionDate:DD-MM HH:mm OK: SecureBootInventory 200`

2. Query data after ~5 minutes:
   ```kql
   SecureBootInventory_CL
   | summarize arg_max(TimeGenerated, *) by ComputerName
   | project ComputerName, SecureBootEnabled, UEFICA2023Status, IsCompliant
   ```

## Data Fields Collected

| Field | Description |
|---|---|
| SecureBootEnabled | UEFI Secure Boot enabled status |
| UEFICA2023Status | Certificate update status (Updated/NotStarted/InProgress/Failed) |
| UEFICA2023Error | Error code if certificate update failed |
| UEFICA2023ErrorEvent | Error event details |
| AvailableUpdates | Available updates hex value |
| HighConfidenceOptOut | High confidence opt-out setting |
| OEMManufacturerName | Device OEM manufacturer |
| OEMModelSystemFamily | Device model family |
| OEMModelNumber | Device model number |
| FirmwareVersion | BIOS/UEFI firmware version |
| FirmwareReleaseDate | Firmware release date |
| OSArchitecture | OS architecture (AMD64, ARM64) |
| CanAttemptUpdateAfter | Earliest allowed update attempt time |
| LatestEventId | Most recent Secure Boot event ID |
| BucketId | Event bucket ID |
| Confidence | Bucket confidence level |
| Event1801Count | Count of Event 1801 (success) |
| Event1808Count | Count of Event 1808 (failure) |
| OSVersion | Windows OS version |
| LastBootTime | Last boot timestamp |
| BaseBoardManufacturer | Baseboard manufacturer |
| BaseBoardProduct | Baseboard product identifier |
| IsCompliant | Overall compliance (SecureBoot + UEFICA2023 Updated) |

## Workbook Sections

- **Compliance Overview** — summary tiles + pie chart
- **UEFI CA 2023 Status** — certificate update status distribution
- **Secure Boot Enabled/Disabled** — fleet-wide Secure Boot state
- **Compliance Trend** — area chart over time
- **Device Details** — full device grid with status icons
- **Non-Compliant Devices** — filtered view with error details
- **Error Analysis** — devices with failed certificate updates
- **Firmware Analysis** — compliance by manufacturer/model/firmware
- **Billing** — data ingestion costs
