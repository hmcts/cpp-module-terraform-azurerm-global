output "tags" {
  value = local.tags
}

output "created_by" {
  value = local.tags.created_by
}

output "created_time" {
  value = local.tags.created_time
}

output "domain" {
  value = local.tags.domain
}
