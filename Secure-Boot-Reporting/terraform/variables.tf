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
