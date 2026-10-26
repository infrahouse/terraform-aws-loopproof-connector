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

variable "enable_control_tower_aggregator_query" {
  type    = bool
  default = null
}
