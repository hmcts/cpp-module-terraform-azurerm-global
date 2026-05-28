module github.com/hmcts/cpp-module-terraform-azurerm-global/tests/terratest

go 1.21

require (
	github.com/gruntwork-io/terratest v0.46.16
	github.com/stretchr/testify v1.8.4
)

// Exclude the accidentally-published split module. It requires the monorepo
// as a transitive dep, causing an "ambiguous import" error since both
// github.com/gruntwork-io/terratest v0.46.16 and this split module provide
// the same package path. Excluding it forces Go to use the monorepo only.
exclude github.com/gruntwork-io/terratest/modules/terraform v0.0.0-20251107042628-de08859c6b2d
