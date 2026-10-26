# Passes every input straight to the module, so the tests can plan it with invalid values. The
# parameters' ARNs name parameters the tests create, so the module's reads find them at plan.
module "connector" {
  source = "../../"

  environment                      = var.environment
  control_plane_account_id         = var.control_plane_account_id
  external_ids_parameter_arn       = var.external_ids_parameter_arn
  registration_token_parameter_arn = var.registration_token_parameter_arn
  event_bus_arn                    = var.event_bus_arn
  registration_url                 = var.registration_url
  severities                       = var.severities
  excluded_accounts                = var.excluded_accounts

  enable_control_tower_aggregator_query = var.enable_control_tower_aggregator_query
}
