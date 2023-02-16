variable "environment_patching_tag" {
  description = "project name e.g. ccm"
  type        = string
  default     = "02011111"
}

variable "platform" {
  description = "platform e.g. nlv or lv"
  type        = string
}

variable "project" {
  description = "project name"
  type        = string
  default     = ""
}

variable "domain" {
  description = "Domain Name"
  type        = string
  default     = ""
}

variable "environment" {
  description = "environment e.g. dev"
  type        = string
}

variable "application" {
  description = "Application name - Natural language. Using of dashes between words."
  type        = string
  default     = ""
}

variable "business_area" {
  description = "Crime only for CPP, it was originally CFT, Crime or Cross-Cutting"
  type        = string
  default     = "Crime"
}

variable "data_classification" {
  description = "Public, Confidential, Strictly Confidential, Internal"
  type        = string
  default     = ""
}

variable "automation" {
  description = "Details on when to backup, stop/start scripts and maintenance window"
  type        = map(string)
  default     = {}
}

variable "costcentre" {
  description = "What is the charge code for this solution"
  type        = string
  default     = ""
}

variable "tier" {
  description = "Front End, Back End, Data Layer"
  type        = string
}

variable "type" {
  description = "VM, Storage, service etc"
  type        = string
  default     = ""
}

variable "criticality" {
  description = "Low, Mid, High. All production Subscription Criticality is High, Dev Subscriptions to be Low or Mid"
  type        = string
  default     = ""
}

variable "note" {
  description = "This is a sample note"
  type        = string
  default     = ""
}

variable "creator" {
  type    = string
  default = "SPT/terraform"
}

variable "owner" {
  type    = string
  default = "HMCTS-SP"
}

variable "expiration_date" {
  type    = string
  default = "none"
}

#Below values are coming from DSL Jenkins

variable "tag_created_time" {
  type        = string
  description = "Timestamp when resource has been created"
}

variable "tag_created_by" {
  type        = string
  description = "User who run the job when resource was created"
}

variable "tag_git_url" {
  type        = string
  description = "GIT URL of the project"
}

variable "tag_git_branch" {
  type        = string
  description = "GIT Branch from where changes being applied"
}

variable "tag_last_apply" {
  type        = string
  description = "Current timestamp when changes applied"
}

variable "tag_last_apply_by" {
  type        = string
  description = "USER ID of the person who is applying the changes"
}

variable "timestamp" {
  type        = string
  description = "timestamp"
  default     = null
}
