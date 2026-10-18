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

variable "external_ids" {
  type      = list(string)
  sensitive = true
}

variable "event_bus_arn" {
  type = string
}

variable "registration_url" {
  type = string
}

variable "registration_token" {
  type      = string
  sensitive = true
  default   = null
}

variable "severities" {
  type    = list(string)
  default = null
}

variable "excluded_accounts" {
  type    = list(string)
  default = null
}
