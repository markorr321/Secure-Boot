# Terraform Deployment

Infrastructure as Code for the Secure Boot Compliance Reporting solution. Deploys all Azure resources needed to collect, store, and visualize Secure Boot compliance data across your fleet.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5.0
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and authenticated (`az login`)
- **Global Administrator** or **Privileged Role Administrator** in Entra ID (required for granting Device.Read.All to the Function App's managed identity)
- **Contributor** access on the target Azure subscription

## Resources Created

| Resource | Name | Purpose |
|----------|------|---------|
| Resource Group | `rg-secure-boot-reporting` | Container for all resources |
| Log Analytics Workspace | `law-secure-boot-reporting` | Stores device inventory data |
| Custom Table | `SecureBootInventory_CL` | 28-column schema for device data |
| Data Collection Endpoint | `dce-secureboot` | Ingestion endpoint for the Logs Ingestion API |
| Data Collection Rule | `dcr-secureboot` | Routes data from DCE to the custom table |
| Storage Account | `stsecboot<random>` | Backing storage for the Function App |
| App Service Plan | `asp-secure-boot-reporting` | Consumption (Y1) plan |
| Windows Function App | `func-secure-boot-reporting-<random>` | Receives data from devices, validates via Graph, ingests to Log Analytics |
| Role Assignment | Monitoring Metrics Publisher | Allows the Function App to write to the DCR |
| App Role Assignment | Device.Read.All | Allows the Function App to validate devices via Microsoft Graph |
| Workbook | Secure Boot Compliance | Dashboard with compliance charts, device details, export, and billing |

## Quick Start

```powershell
# 1. Initialize Terraform
terraform init

# 2. Preview what will be created
terraform plan -var="subscription_id=YOUR-SUBSCRIPTION-ID"

# 3. Deploy
terraform apply -var="subscription_id=YOUR-SUBSCRIPTION-ID"
```

## Variables

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `subscription_id` | Yes | — | Azure Subscription ID to deploy into |
| `location` | No | `centralus` | Azure region for all resources |
| `project_name` | No | `secure-boot-reporting` | Project name used to derive resource names |

## Outputs

| Name | Description |
|------|-------------|
| `function_url` | Azure Function URL — set this in `Invoke-SecureBootCollection.ps1` |
| `workspace_id` | Log Analytics Workspace customer ID |
| `workspace_name` | Log Analytics Workspace name |
| `resource_group_name` | Resource group name |
| `function_app_name` | Function App name |

## Post-Deployment

After `terraform apply` completes:

1. Copy the `function_url` output
2. Update `Invoke-SecureBootCollection.ps1` line 23 with the function URL
3. Deploy the script to devices via Intune Proactive Remediation or scheduled task
4. Data will appear in the workbook within ~5 minutes of the first collection

## Teardown

```powershell
terraform destroy -var="subscription_id=YOUR-SUBSCRIPTION-ID"
```

This removes all Azure resources. The Device.Read.All app role assignment will also be removed.

## Cross-Tenant Deployment

This configuration is fully portable across tenants. All resource IDs and service principal references are resolved dynamically — nothing is hardcoded to a specific tenant. The deployer's `az login` session determines which tenant and subscription are used.

## File Structure

```
terraform/
  main.tf           # Core resources: RG, LAW, custom table, DCR, DCE, role assignments, workbook
  function-app.tf   # Storage account, App Service Plan, Function App, code deployment
  providers.tf      # Provider versions and configuration
  variables.tf      # Input variables
  outputs.tf        # Output values
```
