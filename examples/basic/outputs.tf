output "role_arn" {
  description = "Paste this into LoopProof's onboarding, with region, if the registration call failed."
  value       = module.loopproof_connector.role_arn
}

output "region" {
  description = "Paste this into LoopProof's onboarding with role_arn if the registration call failed."
  value       = module.loopproof_connector.region
}

output "registered" {
  description = "true once LoopProof accepted the registration; null without a token."
  value       = module.loopproof_connector.registered
}
