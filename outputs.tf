output "role_arn" {
  description = <<-EOT
    ARN of the connector role. Before LoopProof has proven your account, paste it into LoopProof's onboarding, with
    region, if the registration call can't succeed, such as from a machine that can't reach LoopProof. After,
    LoopProof takes no paste.
  EOT
  value       = aws_iam_role.connector.arn
}

output "region" {
  description = <<-EOT
    Region the module is applied in, where LoopProof reads the Security Hub findings. Before LoopProof has proven
    your account, paste it into LoopProof's onboarding with role_arn if the registration call can't succeed.
  EOT
  value       = local.region
}

output "role_name" {
  description = "Name of the connector role, loopproof-<environment>-connector."
  value       = aws_iam_role.connector.name
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule that forwards Security Hub findings to LoopProof."
  value       = aws_cloudwatch_event_rule.findings.arn
}

output "excluded_accounts_parameter" {
  description = <<-EOT
    Name of the SSM parameter that publishes excluded_accounts to LoopProof, /loopproof/<environment>/excluded-accounts.
  EOT
  value       = aws_ssm_parameter.excluded_accounts.name
}

output "accept_rules_parameter_path" {
  description = <<-EOT
    Path of the SSM parameters that publish accept_rules to LoopProof, /loopproof/<environment>/accept-rules: one
    String parameter per rule, named by its id.
  EOT
  value       = local.accept_rules_parameter_path
}

output "tenant_settings_parameter" {
  description = <<-EOT
    Name of the SSM parameter that publishes tenant_settings to LoopProof, /loopproof/<environment>/tenant-settings:
    every setting, LoopProof's default for each one left out.
  EOT
  value       = aws_ssm_parameter.tenant_settings.name
}
