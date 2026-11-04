locals {
  module_version = "1.3.0"
  module_name    = "infrahouse/loopproof-connector/aws"

  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id
  # The AWS provider's Region, where the tenant applies the module: Security Hub's home Region.
  region = data.aws_region.current.region

  connector_role_name              = "loopproof-${var.environment}-connector"
  forwarder_role_name              = "loopproof-${var.environment}-forwarder"
  rule_name                        = "loopproof-${var.environment}-findings"
  excluded_accounts_parameter_name = "/loopproof/${var.environment}/excluded-accounts"
  accept_rules_parameter_path      = "/loopproof/${var.environment}/accept-rules"
  # A hierarchical parameter's name starts with "/", which its ARN doesn't repeat. The parameters are in the
  # module's Region, as the excluded accounts' is.
  accept_rules_path_arn = join("", [
    "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter",
    local.accept_rules_parameter_path,
  ])

  # What Part 1 of the install creates both of the tenant's parameters with, until the tenant fills them.
  placeholder = "unset"

  # Decoded only after the read's checks have passed (external_ids.tf), so the placeholder or a malformed
  # value fails there, with a message that names the parameter, never here.
  external_ids = tolist(jsondecode(data.aws_ssm_parameter.external_ids.value))

  # Sorted, so that reordering the list changes neither the rule nor the parameter.
  excluded_accounts = sort(var.excluded_accounts)

  # Both inputs' rules in one shape, each with the kind its input gives it, which a rule doesn't write: a
  # threat rule has no cves, package or image_repositories, and a vulnerability rule no finding_types or
  # behavioral_exception. The input's name is for the size check's message.
  accept_rule_sources = concat(
    [
      for rule in var.threat_accept_rules : {
        input         = "threat_accept_rules"
        id            = rule.id
        kind          = "threat_response"
        reason        = rule.reason
        review_by     = rule.review_by
        decision_ref  = rule.decision_ref
        finding_types = rule.finding_types
        cves          = null
        package       = null
        where = rule.where == null ? null : {
          resource_ids       = rule.where.resource_ids
          tags               = rule.where.tags
          image_repositories = null
          accounts           = rule.where.accounts
        }
        behavioral_exception = rule.behavioral_exception
      }
    ],
    [
      for rule in var.vulnerability_accept_rules : {
        input         = "vulnerability_accept_rules"
        id            = rule.id
        kind          = "vuln_remediation"
        reason        = rule.reason
        review_by     = rule.review_by
        decision_ref  = rule.decision_ref
        finding_types = null
        cves          = rule.cves
        package       = rule.package
        where = rule.where == null ? null : {
          resource_ids       = rule.where.resource_ids
          tags               = rule.where.tags
          image_repositories = rule.where.image_repositories
          accounts           = rule.where.accounts
        }
        behavioral_exception = false
      }
    ],
  )
  accept_rule_inputs = { for rule in local.accept_rule_sources : rule.id => rule.input }

  # Each accept rule as LoopProof reads it, by id: the fields the rule sets and its kind, sorted by name, as
  # jsonencode writes an object, with its lists sorted, so that the same rule publishes the same bytes however
  # it is written, and the plan of a reordered list is empty. A field the rule leaves unset is left out, and so
  # are an empty list or map and a false behavioral_exception, which say no more than an unset field.
  accept_rules = {
    for rule in local.accept_rule_sources : rule.id => jsonencode({
      for field, value in {
        id           = rule.id
        kind         = rule.kind
        reason       = rule.reason
        review_by    = rule.review_by
        decision_ref = rule.decision_ref
        finding_types = (
          rule.finding_types == null ? null : length(rule.finding_types) > 0 ? sort(rule.finding_types) : null
        )
        cves    = rule.cves == null ? null : length(rule.cves) > 0 ? sort(rule.cves) : null
        package = rule.package
        where = rule.where == null ? null : {
          for selector, values in {
            resource_ids = (
              rule.where.resource_ids == null ? null
              : length(rule.where.resource_ids) > 0 ? sort(rule.where.resource_ids) : null
            )
            tags = rule.where.tags == null ? null : length(rule.where.tags) > 0 ? rule.where.tags : null
            image_repositories = (
              rule.where.image_repositories == null ? null
              : length(rule.where.image_repositories) > 0 ? sort(rule.where.image_repositories) : null
            )
            accounts = (
              rule.where.accounts == null ? null
              : length(rule.where.accounts) > 0 ? sort(rule.where.accounts) : null
            )
          } : selector => values if values != null
        }
        behavioral_exception = rule.behavioral_exception ? true : null
      } : field => value if value != null
    })
  }
  # Each rule's length as SSM counts it against a Standard parameter's 4096 characters: in UTF-16 code units, so
  # a character outside the Basic Multilingual Plane, such as an emoji, counts twice, and a combining mark on its
  # own. length() counts grapheme clusters, fewer, so count the code points and add the supplementary ones.
  accept_rule_lengths = {
    for id, value in local.accept_rules : id => (
      length(regexall("(?s).", value)) + length(regexall("[\\x{10000}-\\x{10FFFF}]", value))
    )
  }

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

  # The products whose findings are forwarded at every severity, whatever var.severities lists, by the
  # finding's metadata.product.name as Security Hub writes it. GuardDuty's findings are few, a threat
  # below High is still a threat, and a finding whose severity drops still arrives as an event (IH-65,
  # Aleks, 2026-10-27). Not an input: LoopProof decides what it acts on, and a tenant who forwarded
  # less would hide the events it relies on.
  every_severity_products = ["GuardDuty"]

  # Security Hub sends one finding per "Findings Imported V2" event, at detail.findings[0], for new,
  # updated and closed findings alike. The rule doesn't filter on activity: the control plane drops
  # the echoes of its own updates.
  # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-formats.html
  # A finding is forwarded if its severity_id is among var.severities, or ($or) its product is among
  # every_severity_products. The account filter, beside the $or, applies to both alike.
  # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
  event_pattern = {
    source        = ["aws.securityhub"]
    "detail-type" = ["Findings Imported V2"]
    detail = {
      findings = merge(
        {
          "$or" = [
            { severity_id = [for severity in var.severities : local.severity_ids[severity]] },
            { metadata = { product = { name = local.every_severity_products } } },
          ]
        },
        local.excluded_accounts_filter...
      )
    }
  }

  # The finding's account is cloud.account.uid. "anything-but" with no values isn't a valid pattern, so
  # the filter is there only when an account is excluded. Like the rest of the pattern, it relies on one
  # finding per event: EventBridge matches an array when any element matches, so an event that also held
  # a finding of another account would be forwarded whole.
  excluded_accounts_filter = length(local.excluded_accounts) > 0 ? [
    { cloud = { account = { uid = [{ "anything-but" = local.excluded_accounts }] } } }
  ] : []

  tags = {
    created_by_module     = local.module_name
    loopproof_environment = var.environment
  }
}
