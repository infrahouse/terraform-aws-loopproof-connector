terraform {
  # Ephemeral resources, and ephemeral values in a provisioner's environment, arrived in 1.10.
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # ephemeral "aws_ssm_parameter" arrived in 5.81.0, and data.aws_region's region attribute in 6.0.0.
      version = ">= 6.0"
    }
  }
}
