# --- Random suffix for globally unique names ---
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix       = random_id.suffix.hex
  rg_name      = "rg-${var.project_name}"
  law_name     = "law-${var.project_name}"
  dce_name     = "dce-secureboot"
  dcr_name     = "dcr-secureboot"
  storage_name = "stsecboot${local.suffix}"
  func_name    = "func-${var.project_name}-${local.suffix}"
}

# --- Resource Group ---
resource "azurerm_resource_group" "main" {
  name     = local.rg_name
  location = var.location
}

# --- Log Analytics Workspace ---
resource "azurerm_log_analytics_workspace" "main" {
  name                = local.law_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# --- Custom Table ---
resource "azapi_resource" "table_secureboot" {
  type      = "Microsoft.OperationalInsights/workspaces/tables@2022-10-01"
  name      = "SecureBootInventory_CL"
  parent_id = azurerm_log_analytics_workspace.main.id

  body = {
    properties = {
      schema = {
        name = "SecureBootInventory_CL"
        columns = [
          { name = "TimeGenerated", type = "dateTime" },
          { name = "ManagedDeviceName", type = "string" },
          { name = "ManagedDeviceID", type = "string" },
          { name = "AzureADDeviceID", type = "string" },
          { name = "ComputerName", type = "string" },
          { name = "SecureBootEnabled", type = "string" },
          { name = "UEFICA2023Status", type = "string" },
          { name = "UEFICA2023Error", type = "string" },
          { name = "UEFICA2023ErrorEvent", type = "string" },
          { name = "AvailableUpdates", type = "string" },
          { name = "HighConfidenceOptOut", type = "string" },
          { name = "OEMManufacturerName", type = "string" },
          { name = "OEMModelSystemFamily", type = "string" },
          { name = "OEMModelNumber", type = "string" },
          { name = "FirmwareVersion", type = "string" },
          { name = "FirmwareReleaseDate", type = "string" },
          { name = "OSArchitecture", type = "string" },
          { name = "CanAttemptUpdateAfter", type = "string" },
          { name = "LatestEventId", type = "string" },
          { name = "BucketId", type = "string" },
          { name = "Confidence", type = "string" },
          { name = "Event1801Count", type = "string" },
          { name = "Event1808Count", type = "string" },
          { name = "OSVersion", type = "string" },
          { name = "LastBootTime", type = "string" },
          { name = "BaseBoardManufacturer", type = "string" },
          { name = "BaseBoardProduct", type = "string" },
          { name = "IsCompliant", type = "string" }
        ]
      }
      retentionInDays      = 30
      totalRetentionInDays = 30
      plan                 = "Analytics"
    }
  }
}

# --- Data Collection Endpoint ---
resource "azurerm_monitor_data_collection_endpoint" "main" {
  name                          = local.dce_name
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  public_network_access_enabled = true
}

# --- Data Collection Rule ---
resource "azapi_resource" "dcr" {
  type      = "Microsoft.Insights/dataCollectionRules@2022-06-01"
  name      = local.dcr_name
  location  = azurerm_resource_group.main.location
  parent_id = azurerm_resource_group.main.id

  body = {
    properties = {
      dataCollectionEndpointId = azurerm_monitor_data_collection_endpoint.main.id
      streamDeclarations = {
        "Custom-SecureBootInventory_CL" = {
          columns = [
            { name = "TimeGenerated", type = "datetime" },
            { name = "ManagedDeviceName", type = "string" },
            { name = "ManagedDeviceID", type = "string" },
            { name = "AzureADDeviceID", type = "string" },
            { name = "ComputerName", type = "string" },
            { name = "SecureBootEnabled", type = "string" },
            { name = "UEFICA2023Status", type = "string" },
            { name = "UEFICA2023Error", type = "string" },
            { name = "UEFICA2023ErrorEvent", type = "string" },
            { name = "AvailableUpdates", type = "string" },
            { name = "HighConfidenceOptOut", type = "string" },
            { name = "OEMManufacturerName", type = "string" },
            { name = "OEMModelSystemFamily", type = "string" },
            { name = "OEMModelNumber", type = "string" },
            { name = "FirmwareVersion", type = "string" },
            { name = "FirmwareReleaseDate", type = "string" },
            { name = "OSArchitecture", type = "string" },
            { name = "CanAttemptUpdateAfter", type = "string" },
            { name = "LatestEventId", type = "string" },
            { name = "BucketId", type = "string" },
            { name = "Confidence", type = "string" },
            { name = "Event1801Count", type = "string" },
            { name = "Event1808Count", type = "string" },
            { name = "OSVersion", type = "string" },
            { name = "LastBootTime", type = "string" },
            { name = "BaseBoardManufacturer", type = "string" },
            { name = "BaseBoardProduct", type = "string" },
            { name = "IsCompliant", type = "string" }
          ]
        }
      }
      dataFlows = [
        {
          streams      = ["Custom-SecureBootInventory_CL"]
          destinations = ["logAnalyticsWorkspace"]
          transformKql = "source | extend TimeGenerated = now()"
          outputStream = "Custom-SecureBootInventory_CL"
        }
      ]
      destinations = {
        logAnalytics = [
          {
            workspaceResourceId = azurerm_log_analytics_workspace.main.id
            name                = "logAnalyticsWorkspace"
          }
        ]
      }
    }
  }

  depends_on = [azapi_resource.table_secureboot]
}

# --- Role Assignments ---

resource "azurerm_role_assignment" "func_dcr_publisher" {
  scope                = azapi_resource.dcr.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_windows_function_app.main.identity[0].principal_id
}

data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_app_role_assignment" "device_read" {
  app_role_id         = "7438b122-aefc-4978-80ed-43db9fcc7715"
  principal_object_id = azurerm_windows_function_app.main.identity[0].principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# --- Azure Monitor Workbook ---
resource "azurerm_application_insights_workbook" "secureboot" {
  name                = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  display_name        = "Secure Boot Compliance"
  source_id           = lower(azurerm_log_analytics_workspace.main.id)
  category            = "workbook"
  data_json           = file("${path.module}/../Reporting/SecureBoot/Secure_Boot_Compliance.workbook")
}
