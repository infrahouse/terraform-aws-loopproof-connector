# Self-registration: report the connector role's ARN and the Region to LoopProof, once, with the
# registration token from the tenant's parameter.
#
# LoopProof reads the tenant's Security Hub findings in the Region where the tenant applied this module,
# which onboarding tells them is Security Hub's home Region. An IAM role ARN carries no Region, so the
# call reports the provider's Region beside it; LoopProof can't learn it otherwise.

# Ephemeral, so the token is in neither the plan nor the state. On the install's first apply its ARN is
# unknown at plan, so Terraform opens it during the apply, once the root has created the parameter.
ephemeral "aws_ssm_parameter" "registration_token" {
  arn             = var.registration_token_parameter_arn
  with_decryption = true
}

# The call runs when this resource is created: on the apply that creates the role, again when the role
# is replaced (its ARN is unknown in that plan), and with terraform apply -replace. Later plans and
# applies make none. A failed call fails the apply and leaves the resource tainted, so the next apply,
# once a new token is in the parameter, calls again by itself.
resource "terraform_data" "registration" {
  triggers_replace = aws_iam_role.connector.arn

  provisioner "local-exec" {
    # POSIX sh, so Linux and macOS run it as they are; Windows isn't supported. With an ephemeral value in
    # its environment, Terraform suppresses the script's output, but the error of a failed run shows it
    # all: the script says what to do there, and never prints the token. The token isn't in the command.
    interpreter = ["/bin/sh"]
    command     = "${path.module}/files/register.sh"
    environment = {
      LOOPPROOF_REGISTRATION_TOKEN  = ephemeral.aws_ssm_parameter.registration_token.value
      LOOPPROOF_REGISTRATION_URL    = var.registration_url
      LOOPPROOF_REGISTRATION_BODY   = jsonencode({ role_arn = aws_iam_role.connector.arn, region = local.region })
      LOOPPROOF_TOKEN_PARAMETER_ARN = var.registration_token_parameter_arn
      LOOPPROOF_ROLE_ARN            = aws_iam_role.connector.arn
      LOOPPROOF_REGION              = local.region
    }
  }

  # LoopProof may assume the role as soon as it learns the ARN, and read the excluded accounts with it,
  # so register it with its permissions.
  depends_on = [
    aws_iam_role_policy.connector,
    aws_iam_role_policy.connector_excluded_accounts,
    aws_iam_role_policy.connector_repository_tags,
    aws_iam_role_policy.connector_control_tower_aggregator,
  ]
}
