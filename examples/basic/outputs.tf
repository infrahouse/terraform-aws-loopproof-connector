output "role_arn" {
  description = <<-EOT
    Before LoopProof has proven your account, paste this into LoopProof's onboarding, with region, if the
    registration call can't succeed. After, LoopProof takes no paste.
  EOT
  value       = module.loopproof_connector.role_arn
}

output "region" {
  description = <<-EOT
    Before LoopProof has proven your account, paste this into LoopProof's onboarding with role_arn if the
    registration call can't succeed.
  EOT
  value       = module.loopproof_connector.region
}

output "excluded_accounts_parameter" {
  description = "The SSM parameter where LoopProof reads the excluded accounts."
  value       = module.loopproof_connector.excluded_accounts_parameter
}

output "accept_rules_parameter_path" {
  description = "The SSM path where LoopProof reads the accept rules, one parameter per rule."
  value       = module.loopproof_connector.accept_rules_parameter_path
}

output "tenant_settings_parameter" {
  description = "The SSM parameter where LoopProof reads your settings."
  value       = module.loopproof_connector.tenant_settings_parameter
}
