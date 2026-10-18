variable "region" {
  type        = string
  description = "Security Hub's home Region."
}

variable "external_id_parameter" {
  type        = string
  description = "Name of the SSM parameter (SecureString) that holds LoopProof's ExternalId."
  default     = "/loopproof/external-id"
}

variable "environment" {
  type        = string
  description = "LoopProof's environment, from the generated module call."
}

variable "control_plane_account_id" {
  type        = string
  description = "LoopProof's control-plane account ID, from the generated module call."
}

variable "event_bus_arn" {
  type        = string
  description = "LoopProof's event bus ARN, from the generated module call."
}

variable "registration_url" {
  type        = string
  description = "LoopProof's registration endpoint, from the generated module call."
}

variable "excluded_accounts" {
  type        = list(string)
  description = "AWS accounts to keep out of LoopProof, such as an account outside your audit scope."
  default     = []
}

variable "registration_token" {
  type        = string
  description = "One-time registration token from LoopProof's onboarding. Set it for the first apply only."
  sensitive   = true
  default     = null
}
