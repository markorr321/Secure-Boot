output "function_url" {
  description = "Azure Function URL — set this in Invoke-SecureBootCollection.ps1"
  value       = "https://${azurerm_windows_function_app.main.default_hostname}/api/logcollectorapi"
}

output "workspace_id" {
  description = "Log Analytics Workspace customer ID"
  value       = azurerm_log_analytics_workspace.main.workspace_id
}

output "workspace_name" {
  description = "Log Analytics Workspace name"
  value       = azurerm_log_analytics_workspace.main.name
}

output "resource_group_name" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "function_app_name" {
  description = "Function App name"
  value       = azurerm_windows_function_app.main.name
}
