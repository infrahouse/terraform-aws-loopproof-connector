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
