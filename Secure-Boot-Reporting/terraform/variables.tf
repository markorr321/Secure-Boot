variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralus"
}

variable "project_name" {
  description = "Project name used to derive resource names"
  type        = string
  default     = "secure-boot-reporting"
}

variable "existing_service_plan_id" {
  description = "Resource ID of an existing App Service Plan or ASE-linked plan. If provided, skips creating a new consumption plan."
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "Resource ID of a subnet for VNet integration (e.g., ASE or private network deployments). If provided, the function app will be integrated with the specified subnet."
  type        = string
  default     = null
}
