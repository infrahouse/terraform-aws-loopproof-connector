output "role_arn" {
  description = "Paste this into LoopProof's onboarding, with region, if the registration call can't succeed."
  value       = module.loopproof_connector.role_arn
}

output "region" {
  description = "Paste this into LoopProof's onboarding with role_arn if the registration call can't succeed."
  value       = module.loopproof_connector.region
}

output "excluded_accounts_parameter" {
  description = "The SSM parameter where LoopProof reads the excluded accounts."
  value       = module.loopproof_connector.excluded_accounts_parameter
}
