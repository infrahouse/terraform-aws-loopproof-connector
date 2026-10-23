# The two parts LoopProof's onboarding generates, in one root. Apply it in the account where Security
# Hub collects your findings (the delegated administrator, or your single account), in Security Hub's
# home Region.

terraform {
  # Part 1's write-only placeholder needs 1.11; the module itself, 1.10.
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Part 1: the parameters that hold the ExternalIds and the registration token. Terraform creates them
# with the placeholder "unset", write-only, so it never stores or compares their values; you fill them
# after the first apply.
resource "aws_ssm_parameter" "loopproof_external_ids" {
  name             = "/loopproof/${var.environment}/external-ids"
  description      = "ExternalIds that LoopProof presents to the connector role, as a JSON list."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

resource "aws_ssm_parameter" "loopproof_registration_token" {
  name             = "/loopproof/${var.environment}/registration-token"
  description      = "Registration token from LoopProof's onboarding."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

# Part 2: the connector, which reads both parameters by ARN.
module "loopproof_connector" {
  source = "../../"

  environment                      = var.environment
  control_plane_account_id         = var.control_plane_account_id
  external_ids_parameter_arn       = aws_ssm_parameter.loopproof_external_ids.arn
  registration_token_parameter_arn = aws_ssm_parameter.loopproof_registration_token.arn
  event_bus_arn                    = var.event_bus_arn
  registration_url                 = var.registration_url

  # Accounts whose findings stay here; the next apply takes a change in.
  excluded_accounts = var.excluded_accounts
}
