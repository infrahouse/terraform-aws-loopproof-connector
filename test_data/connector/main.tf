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

module "connector" {
  source = "../../"

  environment              = var.environment
  control_plane_account_id = data.aws_caller_identity.current.account_id
  external_ids             = var.external_ids
  event_bus_arn            = aws_cloudwatch_event_bus.control_plane.arn
  registration_url         = var.registration_url
  registration_token       = var.registration_token
  severities               = var.severities
  excluded_accounts        = var.excluded_accounts
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
