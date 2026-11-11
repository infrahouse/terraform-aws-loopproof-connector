variable "region" {
  type = string
}

variable "role_arn" {
  type    = string
  default = null
}

variable "control_plane_region" {
  type    = string
  default = "us-west-1"
}

variable "environment" {
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

# Any shape, so that each rule names only the fields it needs, as a tenant writes them: rules with
# different fields don't make a list of one type until the module converts them.
variable "threat_accept_rules" {
  type    = any
  default = null
}

variable "vulnerability_accept_rules" {
  type    = any
  default = null
}

# Any shape, so that the tests pass the settings as a tenant writes them, some left out.
variable "tenant_settings" {
  type    = any
  default = null
}
