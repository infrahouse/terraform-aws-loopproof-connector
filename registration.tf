# Self-registration: report the connector role's ARN to LoopProof with the one-time token.
#
# The http data source needs no binary on the tenant's machine. Like any data source, it is read on
# every plan once its inputs are known, so while registration_token is set each plan POSTs again.
# LoopProof answers 200 to a repeat of the same token with the same ARN, which makes that harmless.
# Retries are off on purpose: when they run out, the provider fails with its own error, hiding the
# message below.
data "http" "registration" {
  count = local.register ? 1 : 0

  url    = var.registration_url
  method = "POST"
  request_headers = {
    Authorization = "Bearer ${var.registration_token}"
    Content-Type  = "application/json"
  }
  request_body       = jsonencode({ role_arn = aws_iam_role.connector.arn })
  request_timeout_ms = 30000

  # LoopProof may assume the role as soon as it learns the ARN, so register it with its permissions.
  depends_on = [aws_iam_role_policy.connector]

  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = <<-EOT
        LoopProof did not accept the connector registration (HTTP ${self.status_code}).
        Paste the connector role ARN into LoopProof's onboarding instead:
        ${aws_iam_role.connector.arn}
        Then remove registration_token from the module call and apply again.
      EOT
    }
  }
}
