output "role_arn" {
  description = "ARN of the connector role. Paste it into LoopProof's onboarding if the registration call failed."
  value       = aws_iam_role.connector.arn
}

output "role_name" {
  description = "Name of the connector role, loopproof-<environment>-connector."
  value       = aws_iam_role.connector.name
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule that forwards Security Hub findings to LoopProof."
  value       = aws_cloudwatch_event_rule.findings.arn
}

output "registered" {
  description = "true once LoopProof accepted the registration; null when registration_token is null."
  # The postcondition on data.http.registration fails the run on any answer but 200.
  value = local.register ? data.http.registration[0].status_code == 200 : null
}
