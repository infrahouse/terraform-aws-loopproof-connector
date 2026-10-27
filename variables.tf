variable "environment" {
  type        = string
  description = <<-EOT
    LoopProof's environment, such as staging or production. It names the connector role
    (loopproof-<environment>-connector) and selects the control-plane roles allowed to assume it
    (loopproof-<environment>-*).
  EOT

  validation {
    # 44 characters keep loopproof-<environment>-connector within IAM's 64-character role name limit.
    condition     = can(regex("^[a-z0-9-]{1,44}$", var.environment))
    error_message = <<-EOT
      environment must be 1 to 44 lowercase letters, digits or hyphens, such as "staging" or "production".
      Got: "${var.environment}"
    EOT
  }
}

variable "control_plane_account_id" {
  type        = string
  description = "ID of LoopProof's control-plane AWS account for this environment. Twelve digits."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.control_plane_account_id))
    error_message = <<-EOT
      control_plane_account_id must be a 12-digit AWS account ID.
      Got: "${var.control_plane_account_id}"
    EOT
  }
}

variable "external_ids_parameter_arn" {
  type        = string
  nullable    = false
  description = <<-EOT
    ARN of the SSM SecureString parameter that holds the ExternalIds LoopProof presents when it assumes the
    connector role, as a JSON list: one value, or two during a rotation. Pass the ARN of the parameter your
    root creates, aws_ssm_parameter.<name>.arn, never the value. The module reads it with the AWS
    provider's credentials. Until you fill it, it holds the placeholder "unset", and the apply stops there.
  EOT

  # The message doesn't echo the value: whatever was passed by mistake may be a credential.
  validation {
    condition = can(regex(
      "^arn:aws(-[a-z]+)*:ssm:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:parameter/[A-Za-z0-9_./-]+$",
      var.external_ids_parameter_arn
    ))
    error_message = <<-EOT
      external_ids_parameter_arn must be the ARN of an SSM parameter, such as
      arn:aws:ssm:us-east-1:111122223333:parameter/loopproof/production/external-ids.
      Pass the parameter's ARN, aws_ssm_parameter.<name>.arn, not its name or its value.
    EOT
  }
}

variable "registration_token_parameter_arn" {
  type        = string
  nullable    = false
  description = <<-EOT
    ARN of the SSM SecureString parameter that holds the registration token (lprt_...) from LoopProof's
    onboarding. Pass the ARN of the parameter your root creates, aws_ssm_parameter.<name>.arn, never the
    value. The module reads it as an ephemeral value, so the token is in neither the plan nor the state, and
    uses it once: on the apply that creates the connector role, it reports the role's ARN and the Region to
    registration_url.
  EOT

  # The message doesn't echo the value: whatever was passed by mistake may be the token.
  validation {
    condition = can(regex(
      "^arn:aws(-[a-z]+)*:ssm:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:parameter/[A-Za-z0-9_./-]+$",
      var.registration_token_parameter_arn
    ))
    error_message = <<-EOT
      registration_token_parameter_arn must be the ARN of an SSM parameter, such as
      arn:aws:ssm:us-east-1:111122223333:parameter/loopproof/production/registration-token.
      Pass the parameter's ARN, aws_ssm_parameter.<name>.arn, not its name or its value.
    EOT
  }
}

variable "event_bus_arn" {
  type        = string
  description = "ARN of LoopProof's control-plane EventBridge bus that receives the forwarded findings."

  validation {
    condition = can(regex(
      "^arn:aws(-[a-z]+)*:events:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:event-bus/[A-Za-z0-9._/-]{1,256}$",
      var.event_bus_arn
    ))
    error_message = <<-EOT
      event_bus_arn must be an EventBridge event bus ARN,
      such as arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings.
      Got: "${var.event_bus_arn}"
    EOT
  }
}

variable "registration_url" {
  type        = string
  description = <<-EOT
    LoopProof's connector registration endpoint, such as
    https://api.staging.loopproof.ai/connector/registrations. The module POSTs the connector
    role's ARN and the Region it is applied in there. It must use https://;
    http:// is accepted only for 127.0.0.1 and localhost, for tests.
  EOT

  validation {
    condition = (
      can(regex("^https://[^\\s/?#@]+(/\\S*)?$", var.registration_url))
      || can(regex("^http://(127\\.0\\.0\\.1|localhost)(:[0-9]{1,5})?(/\\S*)?$", var.registration_url))
    )
    error_message = <<-EOT
      registration_url must be an https:// URL (http:// only for 127.0.0.1 or localhost).
      Got: "${var.registration_url}"
    EOT
  }
}

variable "severities" {
  type        = list(string)
  description = <<-EOT
    Severities of the Security Hub findings to forward, as they appear in the OCSF severity field:
    Unknown, Informational, Low, Medium, High, Critical, Fatal or Other. GuardDuty's findings are
    forwarded at every severity, whatever this lists.
  EOT
  default     = ["High", "Critical", "Fatal"]
  nullable    = false

  validation {
    condition     = length(var.severities) > 0
    error_message = "severities must list at least one severity."
  }

  validation {
    condition = alltrue([
      for severity in var.severities :
      contains(["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal", "Other"], severity)
    ])
    error_message = <<-EOT
      severities may only contain Unknown, Informational, Low, Medium, High, Critical, Fatal or Other
      (capitalized as Security Hub writes them). Got: ${jsonencode(var.severities)}
    EOT
  }

  validation {
    condition     = length(distinct(var.severities)) == length(var.severities)
    error_message = "severities must not repeat a value. Got: ${jsonencode(var.severities)}"
  }
}

variable "excluded_accounts" {
  type        = list(string)
  description = <<-EOT
    IDs of the AWS accounts you exclude from LoopProof, such as an account outside your audit scope or a
    decommissioned one. The forwarding rule drops their findings, so they never leave this account, and the
    module publishes the list in the SSM parameter /loopproof/<environment>/excluded-accounts, where LoopProof
    reads it. A change takes effect on the next apply.
  EOT
  default     = []
  nullable    = false

  # The messages name the input but don't echo its values.
  validation {
    condition = alltrue([
      for account_id in var.excluded_accounts : can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = <<-EOT
      excluded_accounts must list 12-digit AWS account IDs, such as "123456789012", without dashes or spaces.
    EOT
  }

  validation {
    condition     = length(distinct(var.excluded_accounts)) == length(var.excluded_accounts)
    error_message = "excluded_accounts must not list an account ID twice."
  }
}
