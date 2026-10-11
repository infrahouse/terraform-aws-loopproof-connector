resource "aws_cloudwatch_event_rule" "findings" {
  name           = local.rule_name
  description    = "Forwards Security Hub findings of the selected severities to LoopProof ${var.environment}."
  event_bus_name = "default"
  event_pattern  = jsonencode(local.event_pattern)
  tags           = local.tags
}

# The control-plane bus is in another account and usually another Region, so EventBridge puts the
# events there with the forwarder role. Until LoopProof has proven the account, the bus refuses them.
resource "aws_cloudwatch_event_target" "control_plane" {
  rule      = aws_cloudwatch_event_rule.findings.name
  target_id = "loopproof-control-plane"
  arn       = var.event_bus_arn
  role_arn  = aws_iam_role.forwarder.arn

  lifecycle {
    precondition {
      condition     = split(":", var.event_bus_arn)[4] == var.control_plane_account_id
      error_message = <<-EOT
        event_bus_arn must be a bus in the control-plane account ${var.control_plane_account_id}.
        Got: "${var.event_bus_arn}"
      EOT
    }
  }
}
