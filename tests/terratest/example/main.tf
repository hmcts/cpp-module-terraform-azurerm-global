
provider "azurerm" {
  features {}
}


module "global" {
  source            = "../../.."
  platform          = var.platform
  environment       = var.environment
  tier              = "apps"
  tag_created_by    = "terratestRun"
  domain            = "cpp.nonlive"
  tag_created_time  = var.tag_created_time
  tag_git_url       = var.tag_git_url
  tag_git_branch    = var.tag_git_branch
  tag_last_apply    = var.tag_last_apply
  tag_last_apply_by = var.tag_last_apply_by
}

locals {
  # Need to revisit tagging and naming convention
  tags = merge(
    module.global.tags,
    module.global.global_tags,
    module.global.global_dynamic_tags,
    {
      tier      = "apps"
      project   = "aks"
      timestamp = ""
    }
  )
}

resource "azurerm_resource_group" "rg1" {
  name     = "testingtags"
  location = var.location
  tags     = local.tags
  lifecycle {
    ignore_changes = [tags["created_by"], tags["created_time"]]
  }
}
