locals {
  module_version = "0.1.0"
  module_name    = "infrahouse/loopproof-connector/aws"

  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id

  connector_role_name = "loopproof-${var.environment}-connector"
  forwarder_role_name = "loopproof-${var.environment}-forwarder"
  rule_name           = "loopproof-${var.environment}-findings"

  # Only the control plane's own roles for this environment may assume the connector role.
  control_plane_iam_prefix   = "arn:${local.partition}:iam::${var.control_plane_account_id}"
  control_plane_root         = "${local.control_plane_iam_prefix}:root"
  control_plane_role_pattern = "${local.control_plane_iam_prefix}:role/loopproof-${var.environment}-*"

  # OCSF severity_id for each severity caption. Security Hub writes both fields; the rule matches
  # severity_id because OCSF requires it, while the caption of 99 (Other) is up to the source.
  # https://schema.ocsf.io/1.6.0/classes/detection_finding (severity_id)
  severity_ids = {
    Unknown       = 0
    Informational = 1
    Low           = 2
    Medium        = 3
    High          = 4
    Critical      = 5
    Fatal         = 6
    Other         = 99
  }

  # Security Hub sends one finding per "Findings Imported V2" event, at detail.findings[0], for new,
  # updated and closed findings alike. The rule doesn't filter on activity: the control plane drops
  # the echoes of its own updates.
  # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-formats.html
  event_pattern = {
    source        = ["aws.securityhub"]
    "detail-type" = ["Findings Imported V2"]
    detail = {
      findings = {
        severity_id = [for severity in var.severities : local.severity_ids[severity]]
      }
    }
  }

  # count can't use a sensitive value; whether a token was given is not itself a secret.
  register = nonsensitive(var.registration_token != null)

  tags = {
    created_by_module     = local.module_name
    loopproof_environment = var.environment
  }
}
