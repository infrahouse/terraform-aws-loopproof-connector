provider "aws" {
  region = var.region

  dynamic "assume_role" {
    for_each = var.role_arn != null ? [var.role_arn] : []
    content {
      role_arn = assume_role.value
    }
  }

  default_tags {
    tags = {
      created_by = "infrahouse/terraform-aws-loopproof-connector"
    }
  }
}

# Stands in for LoopProof's control plane, which runs in another Region than most tenants.
provider "aws" {
  alias  = "control_plane"
  region = var.control_plane_region

  dynamic "assume_role" {
    for_each = var.role_arn != null ? [var.role_arn] : []
    content {
      role_arn = assume_role.value
    }
  }

  default_tags {
    tags = {
      created_by = "infrahouse/terraform-aws-loopproof-connector"
    }
  }
}
