# The ExternalIds, read from the tenant's SecureString parameter with the AWS provider's credentials.
# They are never an input, so they never sit in the root's code or a tfvars file. They do land in the
# state, through the trust policy, which LoopProof's charter accepts (decision 8).
#
# On the install's first apply, the parameter's ARN is unknown at plan, so Terraform reads it during
# the apply, once the root has created the parameter, and the checks below stop the run at the
# placeholder.
data "aws_ssm_parameter" "external_ids" {
  # GetParameter takes an ARN as the name.
  name            = var.external_ids_parameter_arn
  with_decryption = true

  lifecycle {
    # Terraform checks a read's postconditions before anything uses its value, so the placeholder fails
    # here, naming the parameter, and is never decoded.
    postcondition {
      condition     = self.value != local.placeholder
      error_message = <<-EOT
        The SSM parameter ${var.external_ids_parameter_arn} still holds the placeholder "${local.placeholder}".
        Put the ExternalId from LoopProof's onboarding in it, as a JSON list such as ["<ExternalId>"], and apply
        again.
      EOT
    }

    # Skipped for the placeholder, which the check above reports alone. The message doesn't echo the value:
    # it holds credentials.
    postcondition {
      condition = self.value == local.placeholder ? true : try(
        length(tolist(jsondecode(self.value))) >= 1
        && length(tolist(jsondecode(self.value))) <= 2
        && length(distinct(tolist(jsondecode(self.value)))) == length(tolist(jsondecode(self.value)))
        && alltrue([
          for external_id in tolist(jsondecode(self.value)) : can(regex("^[A-Za-z0-9_-]{43}$", external_id))
        ]),
        false
      )
      error_message = <<-EOT
        The SSM parameter ${var.external_ids_parameter_arn} must hold a JSON list of one ExternalId, or two
        during a rotation, such as ["<ExternalId>"]: each exactly 43 characters of A-Z, a-z, 0-9, "_" or "-", as
        LoopProof issued it, and none twice.
      EOT
    }
  }
}
