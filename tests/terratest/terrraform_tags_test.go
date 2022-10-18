package test

import (
	"testing"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)


func TestTerraformSubnet(t *testing.T) {
	t.Parallel()

	terraformOptions := &terraform.Options{
		// The path to where our Terraform code is located
		TerraformDir: "./example",
		VarFiles: []string{"tags.tfvars"},
		Upgrade: true,
	}

	// Defer the destroy to cleanup all created resources
    defer terraform.Destroy(t, terraformOptions)

	// This will init and apply the resources and fail the test if there are any errors
	terraform.InitAndApply(t, terraformOptions)

	// Verify configurations
    outputOne := terraform.Output(t, terraformOptions, "created_by")
	outputTwo := terraform.Output(t, terraformOptions, "created_time")
	outputThree := terraform.Output(t, terraformOptions, "domain")
	assert.Equal(t, "terratestRun", outputOne)
	assert.Equal(t, "terratest", outputTwo)
	assert.Equal(t, "cpp.nonlive", outputThree)
}
