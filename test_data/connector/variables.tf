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

variable "external_ids" {
  type      = list(string)
  sensitive = true
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
