output "role_arn" {
  description = "Paste this into LoopProof's onboarding if the registration call failed."
  value       = module.loopproof_connector.role_arn
}

output "registered" {
  description = "true once LoopProof accepted the registration; null without a token."
  value       = module.loopproof_connector.registered
}
