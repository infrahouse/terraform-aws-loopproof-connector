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

# Any shape, so that each rule names only the fields it needs, as a tenant writes them: rules with
# different fields don't make a list of one type until the module converts them.
variable "threat_accept_rules" {
  type    = any
  default = []
}

variable "vulnerability_accept_rules" {
  type    = any
  default = []
}
