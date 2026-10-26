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
