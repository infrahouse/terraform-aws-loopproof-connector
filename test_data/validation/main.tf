# Passes every input straight to the module, so the tests can plan it with invalid values.
module "connector" {
  source = "../../"

  environment              = var.environment
  control_plane_account_id = var.control_plane_account_id
  external_ids             = var.external_ids
  event_bus_arn            = var.event_bus_arn
  registration_url         = var.registration_url
  registration_token       = var.registration_token
  severities               = var.severities
  excluded_accounts        = var.excluded_accounts
}
