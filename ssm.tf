# The excluded accounts, for LoopProof to read with the connector role, at onboarding and daily after.
# It exists with an empty list too, so that LoopProof can tell a tenant that excludes nothing from a
# connector too old to say.
resource "aws_ssm_parameter" "excluded_accounts" {
  # checkov:skip=CKV2_AWS_34:Account IDs aren't secret, and a String parameter needs no KMS grant to read.
  name        = local.excluded_accounts_parameter_name
  description = "AWS accounts excluded from LoopProof ${var.environment}: the connector doesn't forward their findings."
  type        = "String"
  # Without a tier, the provider uses the Region's default, which the account may have set to Advanced.
  tier = "Standard"
  # Account IDs aren't secret, and the plan of a change to the list should show it.
  insecure_value = jsonencode(local.excluded_accounts)
  tags           = local.tags
}

# The accept rules (IH-60), one parameter per rule, named by its id, for LoopProof to read with the connector
# role: all of them by path, every 15 minutes, and at once when a tenant's admin asks. One parameter per
# rule keeps each within a Standard parameter's 4096 characters. None exists without a rule.
resource "aws_ssm_parameter" "accept_rules" {
  # checkov:skip=CKV2_AWS_34:A rule isn't secret, and a String parameter needs no KMS grant to read.
  for_each = local.accept_rules

  name        = "${local.accept_rules_parameter_path}/${each.key}"
  description = "Accept rule ${each.key} for LoopProof ${var.environment}, from the connector's accept rules."
  type        = "String"
  # Without a tier, the provider uses the Region's default, which the account may have set to Advanced.
  tier = "Standard"
  # A rule isn't secret, and the plan of a change to it should show it.
  insecure_value = each.value
  tags           = local.tags

  lifecycle {
    precondition {
      # Through the lengths, not each.value: Terraform prints the values a failed condition refers to, and the
      # message names the rule by its id alone.
      condition = local.accept_rule_lengths[each.key] <= 4096
      error_message = join("", [
        "${local.accept_rule_inputs[each.key]}: a rule must fit in 4096 characters as JSON. ",
        "Rules: ${jsonencode(each.key)}.",
      ])
    }
  }
}

# The tenant's settings (IH-156), for LoopProof to read with the connector role every 15 minutes. It always holds
# every setting, LoopProof's defaults when the tenant sets none, so that LoopProof can tell a tenant on the defaults
# from a connector too old to say. One Standard parameter holds them: the value is a few hundred characters.
resource "aws_ssm_parameter" "tenant_settings" {
  # checkov:skip=CKV2_AWS_34:The settings aren't secret, and a String parameter needs no KMS grant to read.
  name = local.tenant_settings_parameter_name
  description = join(" ", [
    "Settings of the tenant in LoopProof ${var.environment}:",
    "SLA targets, thresholds, quiet window, ticket budget and review due.",
  ])
  type = "String"
  # Without a tier, the provider uses the Region's default, which the account may have set to Advanced.
  tier = "Standard"
  # The settings aren't secret, and the plan of a change to them, which the tenant's pull request approves,
  # should show it.
  insecure_value = jsonencode(local.tenant_settings)
  tags           = local.tags
}
