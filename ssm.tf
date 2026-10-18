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
