variable "region" {
  type        = string
  description = "Security Hub's home Region."
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

# Any shape, so that each rule names only the fields it needs; the module checks each rule at plan. See
# "Accepting risks" in the module's README, for example:
#
#   accept_rules = [{
#     id            = "vpn-port-probes"
#     kind          = "threat_response"
#     finding_types = ["Recon:EC2/PortProbeUnprotectedPort"]
#     where         = { tags = { role = "vpn" } }
#     reason        = "VPN endpoints are public by design"
#     review_by     = "2027-03-31"
#     decision_ref  = "SEC-42"
#   }]
variable "accept_rules" {
  type        = any
  description = "Your accept rules: the risks you accept, each with its register entry in Linear."
  default     = []
}
