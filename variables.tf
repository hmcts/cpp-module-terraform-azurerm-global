variable "environment_patching_tag" {
  description = "project name e.g. ccm"
  type        = string
  default     = "02011111"
}

variable "platform" {
  description = "platform e.g. nlv or lv"
  type        = string
}

variable "environment" {
  description = "environment e.g. dev"
  type        = string
}

variable "tier" {
  description = "tier e.g. ccm "
  type        = string
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