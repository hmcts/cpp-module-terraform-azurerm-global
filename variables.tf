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
