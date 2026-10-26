# In the tests, the "control plane" is the test account itself.

data "aws_caller_identity" "current" {}

# The role Terraform runs as; the tests assume the probe roles from it.
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

resource "aws_cloudwatch_event_bus" "control_plane" {
  provider = aws.control_plane
  name     = "loopproof-${var.environment}-findings"
}

# Part 1, as the README tells a tenant to write it: the two parameters, each created with the
# write-only placeholder "unset", which the tests then fill as a tenant does.
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
  severities                       = var.severities
  excluded_accounts                = var.excluded_accounts

  enable_control_tower_aggregator_query = var.enable_control_tower_aggregator_query
}

# Stands in for a repository of the tenant's, whose tags LoopProof reads with the connector role.
resource "aws_ecr_repository" "tagged" {
  name         = "loopproof-${var.environment}-tagged"
  force_delete = true

  tags = {
    team = "loopproof-pytest"
  }
}

# Probe roles stand in for the control plane's roles. "probe" matches loopproof-<environment>-*,
# "outsider" doesn't. Both may call sts:AssumeRole on the connector role, so a denial for the
# outsider comes from the connector's trust policy, not from the outsider's own permissions.

data "aws_iam_policy_document" "probe_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_iam_session_context.current.issuer_arn]
    }
  }
}

data "aws_iam_policy_document" "probe_permissions" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [module.connector.role_arn]
  }
}

resource "aws_iam_role" "probe" {
  name               = "loopproof-${var.environment}-probe"
  assume_role_policy = data.aws_iam_policy_document.probe_trust.json
}

resource "aws_iam_role_policy" "probe" {
  name   = "assume-connector"
  role   = aws_iam_role.probe.id
  policy = data.aws_iam_policy_document.probe_permissions.json
}

resource "aws_iam_role" "outsider" {
  name               = "outsider-${var.environment}-probe"
  assume_role_policy = data.aws_iam_policy_document.probe_trust.json
}

resource "aws_iam_role_policy" "outsider" {
  name   = "assume-connector"
  role   = aws_iam_role.outsider.id
  policy = data.aws_iam_policy_document.probe_permissions.json
}
