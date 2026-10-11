# The module call LoopProof's onboarding generates, with the ExternalId read from your own
# parameter store instead of written into the code.
#
# Apply it in the account where Security Hub collects your findings (the delegated
# administrator, or your single account), in Security Hub's home Region.

provider "aws" {
  region = var.region
}

data "aws_ssm_parameter" "loopproof_external_id" {
  name = var.external_id_parameter
}

module "loopproof_connector" {
  source = "../../"

  environment              = var.environment
  control_plane_account_id = var.control_plane_account_id
  external_ids             = [data.aws_ssm_parameter.loopproof_external_id.value]
  event_bus_arn            = var.event_bus_arn
  registration_url         = var.registration_url

  # Set for the first apply only, for example with TF_VAR_registration_token. Then remove it.
  registration_token = var.registration_token
}
