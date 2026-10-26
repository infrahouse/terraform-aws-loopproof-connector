# A tenant's root as the README writes it, which the upgrade test installs at the previous release
# first: it writes main_override.tf with the registry's source and that version, then removes it.

data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_event_bus" "control_plane" {
  provider = aws.control_plane
  name     = "loopproof-${var.environment}-findings"
}

resource "aws_ssm_parameter" "loopproof_external_ids" {
  name             = "/loopproof/${var.environment}/external-ids"
  description      = "ExternalIds that LoopProof ${var.environment} presents to the connector role, as a JSON list."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

resource "aws_ssm_parameter" "loopproof_registration_token" {
  name             = "/loopproof/${var.environment}/registration-token"
  description      = "Registration token from LoopProof ${var.environment}'s onboarding."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

module "connector" {
  source = "../../"

  environment                      = var.environment
  control_plane_account_id         = data.aws_caller_identity.current.account_id
  external_ids_parameter_arn       = aws_ssm_parameter.loopproof_external_ids.arn
  registration_token_parameter_arn = aws_ssm_parameter.loopproof_registration_token.arn
  event_bus_arn                    = aws_cloudwatch_event_bus.control_plane.arn
  registration_url                 = var.registration_url
}
