variable "region" {
  type = string
}

variable "role_arn" {
  type    = string
  default = null
}

variable "environment" {
  type = string
}

variable "control_plane_account_id" {
  type = string
}

variable "external_ids_parameter_arn" {
  type = string
}

variable "registration_token_parameter_arn" {
  type = string
}

variable "event_bus_arn" {
  type = string
}

variable "registration_url" {
  type = string
}

variable "severities" {
  type    = list(string)
  default = null
}

variable "excluded_accounts" {
  type    = list(string)
  default = null
}

# Any shape, so that the validation tests can pass rules the module's type refuses.
variable "threat_accept_rules" {
  type    = any
  default = null
}

variable "vulnerability_accept_rules" {
  type    = any
  default = null
}

# Any shape, so that the tests can pass settings the module refuses, as a tenant writes them.
variable "tenant_settings" {
  type    = any
  default = null
}
