locals {
  module_version = "1.0.1"
  module_name    = "infrahouse/loopproof-connector/aws"

  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id
  # The AWS provider's Region, where the tenant applies the module: Security Hub's home Region.
  region = data.aws_region.current.region

  connector_role_name              = "loopproof-${var.environment}-connector"
  forwarder_role_name              = "loopproof-${var.environment}-forwarder"
  rule_name                        = "loopproof-${var.environment}-findings"
  excluded_accounts_parameter_name = "/loopproof/${var.environment}/excluded-accounts"

  # AWS Control Tower's AWS Config aggregator, in the Audit account and Control Tower's home Region. IAM names
  # it by an ARN that ends in an ID AWS Config generates, so the module looks it up by this name.
  control_tower_aggregator_name = "aws-controltower-GuardrailsComplianceAggregator"

  # What Part 1 of the install creates both of the tenant's parameters with, until the tenant fills them.
  placeholder = "unset"

  # Decoded only after the read's checks have passed (external_ids.tf), so the placeholder or a malformed
  # value fails there, with a message that names the parameter, never here.
  external_ids = tolist(jsondecode(data.aws_ssm_parameter.external_ids.value))

  # Sorted, so that reordering the list changes neither the rule nor the parameter.
  excluded_accounts = sort(var.excluded_accounts)

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
      findings = merge(
        { severity_id = [for severity in var.severities : local.severity_ids[severity]] },
        local.excluded_accounts_filter...
      )
    }
  }

  # The finding's account is cloud.account.uid. "anything-but" with no values isn't a valid pattern, so
  # the filter is there only when an account is excluded, and a tenant who excludes none keeps the
  # pattern it had before. Like the rest of the pattern, it relies on one finding per event:
  # EventBridge matches an array when any element matches, so an event that also held a finding of
  # another account would be forwarded whole.
  excluded_accounts_filter = length(local.excluded_accounts) > 0 ? [
    { cloud = { account = { uid = [{ "anything-but" = local.excluded_accounts }] } } }
  ] : []

  tags = {
    created_by_module     = local.module_name
    loopproof_environment = var.environment
  }
}
