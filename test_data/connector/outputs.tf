output "role_arn" {
  value = module.connector.role_arn
}

output "region" {
  value = module.connector.region
}

output "role_name" {
  value = module.connector.role_name
}

output "event_rule_arn" {
  value = module.connector.event_rule_arn
}

output "registered" {
  value = module.connector.registered
}

output "event_bus_arn" {
  value = aws_cloudwatch_event_bus.control_plane.arn
}

output "probe_role_arn" {
  value = aws_iam_role.probe.arn
}

output "outsider_role_arn" {
  value = aws_iam_role.outsider.arn
}
