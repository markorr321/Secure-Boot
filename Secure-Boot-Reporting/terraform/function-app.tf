# --- Storage Account for Function App ---
resource "azurerm_storage_account" "func" {
  name                     = local.storage_name
  location                 = azurerm_resource_group.main.location
  resource_group_name      = azurerm_resource_group.main.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# --- App Service Plan (Consumption) ---
# Skipped when an existing plan is provided via var.existing_service_plan_id
resource "azurerm_service_plan" "func" {
  count               = var.existing_service_plan_id == null ? 1 : 0
  name                = "asp-${var.project_name}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Windows"
  sku_name            = "Y1"
}

# --- Function App ---
resource "azurerm_windows_function_app" "main" {
  name                       = local.func_name
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  service_plan_id            = var.existing_service_plan_id != null ? var.existing_service_plan_id : azurerm_service_plan.func[0].id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key
  virtual_network_subnet_id  = var.subnet_id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      powershell_core_version = "7.4"
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "powershell"
    DCE_ENDPOINT             = azurerm_monitor_data_collection_endpoint.main.logs_ingestion_endpoint
    DCR_IMMUTABLE_ID         = azapi_resource.dcr.output.properties.immutableId
    SECUREBOOT_STREAM_NAME   = "Custom-SecureBootInventory_CL"
  }
}

# --- Function Code Deployment ---
data "archive_file" "function_code" {
  type        = "zip"
  source_dir  = "${path.module}/../SecureBootFunction"
  output_path = "${path.module}/function-deploy.zip"
  excludes    = ["local.settings.json"]
}

resource "null_resource" "deploy_function_code" {
  triggers = {
    code_hash = data.archive_file.function_code.output_sha256
  }

  provisioner "local-exec" {
    command = "az functionapp deployment source config-zip --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_windows_function_app.main.name} --src ${data.archive_file.function_code.output_path}"
  }

  depends_on = [azurerm_windows_function_app.main]
}
