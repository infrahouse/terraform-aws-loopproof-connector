# Self-registration: report the connector role's ARN and the Region to LoopProof with the one-time token.
#
# LoopProof reads the tenant's Security Hub findings in the Region where the tenant applied this module,
# which onboarding tells them is Security Hub's home Region. An IAM role ARN carries no Region, so the
# call reports the provider's Region beside it; LoopProof can't learn it otherwise.
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
  request_body = jsonencode({
    role_arn = aws_iam_role.connector.arn
    region   = local.region
  })
  request_timeout_ms = 30000

  # LoopProof may assume the role as soon as it learns the ARN, and read the excluded accounts with it,
  # so register it with its permissions.
  depends_on = [aws_iam_role_policy.connector, aws_iam_role_policy.connector_excluded_accounts]

  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = <<-EOT
        LoopProof did not accept the connector registration (HTTP ${self.status_code}).
        Paste the connector role ARN and the Region into LoopProof's onboarding instead:
        Role ARN: ${aws_iam_role.connector.arn}
        Region: ${local.region}
        Then remove registration_token from the module call and apply again.
      EOT
    }
  }
}
