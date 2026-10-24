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
