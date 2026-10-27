# The connector role: LoopProof's control plane assumes it to read findings and update their
# status and comment, and to read the tags of the resources the findings relate to, from ECR and from
# AWS Config aggregators, whose queries return any configuration an aggregator holds, not only tags.

data "aws_iam_policy_document" "connector_trust" {
  statement {
    sid     = "LoopProofControlPlane"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.control_plane_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = [local.control_plane_role_pattern]
    }

    # Two values during a rotation, so the old ExternalId keeps working until LoopProof switches.
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = local.external_ids
    }
  }
}

# The V2 APIs have no IAM actions of their own: GetFindingsV2 is authorized as securityhub:GetFindings
# and BatchUpdateFindingsV2 as securityhub:BatchUpdateFindings. Neither action requires a resource type
# (hub and hubv2 are optional), and neither lists dependent actions.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_securityhub.html
# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html
# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchUpdateFindingsV2.html
data "aws_iam_policy_document" "connector_permissions" {
  statement {
    sid       = "ReadFindings"
    actions   = ["securityhub:GetFindings"]
    resources = ["*"]
  }

  statement {
    sid       = "UpdateFindings"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]
  }

  # LoopProof sets a finding's status and comment, never its severity.
  statement {
    sid       = "DenySeverityUpdates"
    effect    = "Deny"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "securityhub:OCSFSyntaxPath/SeverityId"
      values   = ["false"]
    }
  }

  # securityhub:BatchUpdateFindings also authorizes the ASFF BatchUpdateFindings API, whose requests
  # carry no OCSF fields. Requiring StatusId or Comment confines the role to BatchUpdateFindingsV2.
  statement {
    sid       = "DenyUpdatesWithoutStatusOrComment"
    effect    = "Deny"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "securityhub:OCSFSyntaxPath/StatusId"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "securityhub:OCSFSyntaxPath/Comment"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "connector" {
  name = local.connector_role_name
  description = join(" ", [
    "Lets LoopProof ${var.environment} read Security Hub findings and set their status and comment,",
    "read ECR repositories' tags, and query AWS Config aggregators, which return any configuration they hold.",
  ])
  # The trust policy holds the ExternalIds. Terraform doesn't carry the parameter value's sensitivity into
  # the policy document's JSON, so mark it here to keep the ExternalIds out of plan output.
  assume_role_policy = sensitive(data.aws_iam_policy_document.connector_trust.json)

  tags = merge(
    local.tags,
    {
      module_version = local.module_version
    }
  )
}

resource "aws_iam_role_policy" "connector" {
  name   = "security-hub-findings"
  role   = aws_iam_role.connector.id
  policy = data.aws_iam_policy_document.connector_permissions.json
}

# LoopProof reads the excluded accounts with the connector role. KMS encrypts only SecureString
# parameters, so reading a String parameter takes no KMS permission.
# https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html
data "aws_iam_policy_document" "connector_excluded_accounts" {
  statement {
    sid       = "ReadExcludedAccounts"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.excluded_accounts.arn]
  }
}

resource "aws_iam_role_policy" "connector_excluded_accounts" {
  name   = "excluded-accounts-parameter"
  role   = aws_iam_role.connector.id
  policy = data.aws_iam_policy_document.connector_excluded_accounts.json
}

# Resource tags. Where a finding's resource carries no tags, LoopProof derives them from a related resource:
# an ECR image's from its repository, which neither Inspector's nor Security Hub's finding carries.

# The direct read, of this account's repositories. Every Region: Security Hub's home Region collects the
# linked Regions' findings, and a repository is in its finding's Region. tag:GetResources would serve too,
# but takes no resource ARN and reads every tagged resource; ecr:ListTagsForResource can be held to
# repositories. It has no dependent actions, and tags aren't encrypted, so it needs no KMS permission.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticcontainerregistry.html
data "aws_iam_policy_document" "connector_repository_tags" {
  statement {
    sid       = "ReadRepositoryTags"
    actions   = ["ecr:ListTagsForResource"]
    resources = ["arn:${local.partition}:ecr:*:${local.account_id}:repository/*"]
  }
}

resource "aws_iam_role_policy" "connector_repository_tags" {
  name   = "ecr-repository-tags"
  role   = aws_iam_role.connector.id
  policy = data.aws_iam_policy_document.connector_repository_tags.json
}

# The aggregator query, for a tenant with AWS Control Tower, whose Config aggregator in the Audit account,
# aws-controltower-GuardrailsComplianceAggregator, holds the tags of the organization's resources. IAM
# names an aggregator by an ARN that ends in an ID AWS Config generates, not its name, so the grant covers
# every aggregator of the account in the module's Region (Aleks, 2026-10-27): no lookup, and for a tenant
# without one it matches nothing. LoopProof needs nothing to find it: SelectAggregateResourceConfig takes
# the aggregator's name.
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsconfig.html
data "aws_iam_policy_document" "connector_config_aggregator" {
  statement {
    sid       = "QueryConfigAggregators"
    actions   = ["config:SelectAggregateResourceConfig"]
    resources = ["arn:${local.partition}:config:${local.region}:${local.account_id}:config-aggregator/*"]
  }
}

resource "aws_iam_role_policy" "connector_config_aggregator" {
  name   = "config-aggregator-query"
  role   = aws_iam_role.connector.id
  policy = data.aws_iam_policy_document.connector_config_aggregator.json
}

# The forwarder role: EventBridge assumes it to put the matching findings on the control-plane bus.

data "aws_iam_policy_document" "forwarder_trust" {
  statement {
    sid     = "EventBridgeFindingsRule"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.findings.arn]
    }
  }
}

data "aws_iam_policy_document" "forwarder_permissions" {
  statement {
    sid       = "PutEventsOnControlPlaneBus"
    actions   = ["events:PutEvents"]
    resources = [var.event_bus_arn]
  }
}

resource "aws_iam_role" "forwarder" {
  name               = local.forwarder_role_name
  description        = "Lets EventBridge forward Security Hub findings to LoopProof ${var.environment}."
  assume_role_policy = data.aws_iam_policy_document.forwarder_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "forwarder" {
  name   = "put-events"
  role   = aws_iam_role.forwarder.id
  policy = data.aws_iam_policy_document.forwarder_permissions.json
}
