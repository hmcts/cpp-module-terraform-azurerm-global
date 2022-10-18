variable "environment_patching_tag" {
  description = "project name e.g. ccm"
  type        = string
  default     = "02011111"
}

variable "location" {}

variable "platform" {
  description = "platform e.g. nlv or lv"
  type        = string
  default     = "nlv"
}

variable "environment" {
  description = "environment e.g. dev"
  type        = string
  default     = "terratest"
}

variable "tier" {
  description = "tier e.g. ccm "
  type        = string
  default     = "terratest"
}

#Below values are coming from DSL Jenkins

variable "tag_created_time" {
  type        = string
  description = "Timestamp when resource has been created"
  default     = "terratest"
}

variable "tag_created_by" {
  type        = string
  description = "User who run the job when resource was created"
  default     = "terratest"
}

variable "tag_git_url" {
  type        = string
  description = "GIT URL of the project"
  default     = "terratest"
}

variable "tag_git_branch" {
  type        = string
  description = "GIT Branch from where changes being applied"
  default     = "terratest"
}

variable "tag_last_apply" {
  type        = string
  description = "Current timestamp when changes applied"
  default     = "terratest"
}

variable "tag_last_apply_by" {
  type        = string
  description = "USER ID of the person who is applying the changes"
  default     = "terratest"
}
