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

variable "threat_accept_rules" {
  # reason, review_by and decision_ref are required, but optional in the type, so that the checks below can
  # name the rule that lacks one: Terraform's own error names only its place in the list. Terraform drops an
  # attribute the type doesn't name without an error, so a misspelled field, or a vulnerability rule's field
  # such as cves, is missing from the rule's published value, which the plan shows.
  type = list(object({
    id           = string
    reason       = optional(string)
    review_by    = optional(string)
    decision_ref = optional(string)

    # What the rule accepts: GuardDuty's finding types.
    finding_types = optional(list(string))

    # Where: at least one of resource_ids and tags; accounts only narrows them.
    where = optional(object({
      resource_ids = optional(list(string))
      tags         = optional(map(string))
      accounts     = optional(list(string))
    }))

    behavioral_exception = optional(bool, false)
  }))
  description = <<-EOT
    The threats you accept, GuardDuty's findings, each rule with its register entry in Linear. The module
    publishes each rule as JSON, with the kind threat_response, in the SSM parameter
    /loopproof/<environment>/accept-rules/<id>, where LoopProof reads it with the connector role, and checks
    each rule's shape at plan. LoopProof judges what a rule means when it loads it: the behavioral denylist, an
    exception rule's limits, and the register entry. See "Accepting risks" in the README.
  EOT
  default     = []
  nullable    = false

  # Each message names the input and the ids of the rules it refuses, and no other value of theirs.
  validation {
    condition     = alltrue([for rule in var.threat_accept_rules : rule != null])
    error_message = "threat_accept_rules must not hold a null rule."
  }

  # The id names the rule's parameter.
  validation {
    condition = length(distinct([for rule in var.threat_accept_rules : rule.id if rule != null])) == length(
      [for rule in var.threat_accept_rules : rule.id if rule != null]
    )
    error_message = join("", [
      "threat_accept_rules: no two rules may have the same id. Rules: ",
      join(", ", [
        for id in distinct([for rule in var.threat_accept_rules : rule.id if rule != null]) : jsonencode(id)
        if length([for rule in var.threat_accept_rules : rule.id if rule == null ? false : rule.id == id]) > 1
      ]),
      ".",
    ])
  }

  # The id names the rule's parameter, and LoopProof's suppressions cite it.
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        !can(regex("^[a-z0-9][a-z0-9-]{0,63}$", rule.id))
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule's id must be 1 to 64 lowercase letters, digits or hyphens, starting with",
      " a letter or digit. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          !can(regex("^[a-z0-9][a-z0-9-]{0,63}$", rule.id))
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.reason == null ? true : trimspace(rule.reason) == ""
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule must give its reason. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.reason == null ? true : trimspace(rule.reason) == ""
        )
      ]),
      ".",
    ])
  }

  # A real date: formatdate refuses a day the month doesn't have.
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.review_by == null ? true : !(
          can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", rule.review_by))
          && can(formatdate("YYYY", "${rule.review_by}T00:00:00Z"))
        )
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule's review_by must be a date, YYYY-MM-DD. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.review_by == null ? true : !(
            can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", rule.review_by))
            && can(formatdate("YYYY", "${rule.review_by}T00:00:00Z"))
          )
        )
      ]),
      ".",
    ])
  }

  # The format only: whether the register entry exists is LoopProof's to check, in Linear.
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.decision_ref == null ? true : !can(
          regex("^[A-Z][A-Z0-9]*-[1-9][0-9]*$", rule.decision_ref)
        )
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule's decision_ref must be its register entry's Linear issue identifier, ",
      "such as SEC-42. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.decision_ref == null ? true : !can(
            regex("^[A-Z][A-Z0-9]*-[1-9][0-9]*$", rule.decision_ref)
          )
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        !(rule.finding_types == null ? false : length(rule.finding_types) > 0)
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule must name the finding_types it accepts. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          !(rule.finding_types == null ? false : length(rule.finding_types) > 0)
        )
      ]),
      ".",
    ])
  }

  # GuardDuty's types are ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism!Artifact, so
  # a wildcard or a part alone is refused here. Whether a type is denylisted is LoopProof's to judge.
  # https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.finding_types == null ? false : !alltrue([
          for finding_type in rule.finding_types :
          can(regex("^[A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9&.!_-]+$", finding_type))
        ])
      )
    ])
    error_message = join("", [
      "threat_accept_rules: finding_types must be GuardDuty finding types, each in full, such as ",
      "Recon:EC2/PortProbeUnprotectedPort. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.finding_types == null ? false : !alltrue([
            for finding_type in rule.finding_types :
            can(regex("^[A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9&.!_-]+$", finding_type))
          ])
        )
      ]),
      ".",
    ])
  }

  # An account alone would accept everything in it, so it only narrows a rule (IH-60, 2026-11-04).
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.where == null ? true : !(
          (rule.where.resource_ids == null ? false : length(rule.where.resource_ids) > 0)
          || (rule.where.tags == null ? false : length(rule.where.tags) > 0)
        )
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule's where must name resource_ids or tags; accounts only narrows them. ",
      "Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? true : !(
            (rule.where.resource_ids == null ? false : length(rule.where.resource_ids) > 0)
            || (rule.where.tags == null ? false : length(rule.where.tags) > 0)
          )
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.where == null ? false : (rule.where.accounts == null ? false : !alltrue([
          for account_id in rule.where.accounts : can(regex("^[0-9]{12}$", account_id))
        ]))
      )
    ])
    error_message = join("", [
      "threat_accept_rules: where.accounts must list 12-digit AWS account IDs. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? false : (rule.where.accounts == null ? false : !alltrue([
            for account_id in rule.where.accounts : can(regex("^[0-9]{12}$", account_id))
          ]))
        )
      ]),
      ".",
    ])
  }

  # Exact values: no wildcard, and no blank resource id, repository or tag key.
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        rule.where == null ? false : !alltrue(concat(
          [
            for value in(rule.where.resource_ids == null ? [] : rule.where.resource_ids) :
            can(regex("^[^*\\s]+$", value))
          ],
          [
            for key, value in(rule.where.tags == null ? {} : rule.where.tags) :
            can(regex("^[^*]*[^*\\s][^*]*$", key)) && can(regex("^[^*]*$", value))
          ],
        ))
      )
    ])
    error_message = join("", [
      "threat_accept_rules: where's resource_ids and tags must be values in full. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? false : !alltrue(concat(
            [
              for value in(rule.where.resource_ids == null ? [] : rule.where.resource_ids) :
              can(regex("^[^*\\s]+$", value))
            ],
            [
              for key, value in(rule.where.tags == null ? {} : rule.where.tags) :
              can(regex("^[^*]*[^*\\s][^*]*$", key)) && can(regex("^[^*]*$", value))
            ],
          ))
        )
      ]),
      ".",
    ])
  }

  # A value listed twice would publish other bytes than the same rule without the repeat.
  validation {
    condition = alltrue([
      for rule in var.threat_accept_rules : rule == null ? true : !(
        (rule.finding_types == null ? false : (
          length(distinct(rule.finding_types)) < length(rule.finding_types)
        ))
        || (rule.where == null ? false : rule.where.resource_ids == null ? false : (
          length(distinct(rule.where.resource_ids)) < length(rule.where.resource_ids)
        ))
        || (rule.where == null ? false : rule.where.accounts == null ? false : (
          length(distinct(rule.where.accounts)) < length(rule.where.accounts)
        ))
      )
    ])
    error_message = join("", [
      "threat_accept_rules: a rule must not list a value twice in finding_types, where.resource_ids or ",
      "where.accounts. Rules: ",
      join(", ", [
        for rule in var.threat_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          (rule.finding_types == null ? false : (
            length(distinct(rule.finding_types)) < length(rule.finding_types)
          ))
          || (rule.where == null ? false : rule.where.resource_ids == null ? false : (
            length(distinct(rule.where.resource_ids)) < length(rule.where.resource_ids)
          ))
          || (rule.where == null ? false : rule.where.accounts == null ? false : (
            length(distinct(rule.where.accounts)) < length(rule.where.accounts)
          ))
        )
      ]),
      ".",
    ])
  }
}

variable "vulnerability_accept_rules" {
  # reason, review_by and decision_ref are required, but optional in the type, so that the checks below can
  # name the rule that lacks one: Terraform's own error names only its place in the list. Terraform drops an
  # attribute the type doesn't name without an error, so a misspelled field, or a threat rule's field such as
  # finding_types, is missing from the rule's published value, which the plan shows.
  type = list(object({
    id           = string
    reason       = optional(string)
    review_by    = optional(string)
    decision_ref = optional(string)

    # What the rule accepts: cves, or a source package.
    cves = optional(list(string))
    package = optional(object({
      name    = optional(string)
      version = optional(string)
    }))

    # Where: at least one of resource_ids, tags and image_repositories; accounts only narrows them.
    where = optional(object({
      resource_ids       = optional(list(string))
      tags               = optional(map(string))
      image_repositories = optional(list(string))
      accounts           = optional(list(string))
    }))
  }))
  description = <<-EOT
    The vulnerabilities you accept, each rule with its register entry in Linear. The module publishes each rule
    as JSON, with the kind vuln_remediation, in the SSM parameter /loopproof/<environment>/accept-rules/<id>,
    where LoopProof reads it with the connector role, and checks each rule's shape at plan. LoopProof judges
    what a rule means when it loads it, and checks its register entry. An id must not be a threat rule's too.
    See "Accepting risks" in the README.
  EOT
  default     = []
  nullable    = false

  # Each message names the input and the ids of the rules it refuses, and no other value of theirs.
  validation {
    condition     = alltrue([for rule in var.vulnerability_accept_rules : rule != null])
    error_message = "vulnerability_accept_rules must not hold a null rule."
  }

  # The id names the rule's parameter.
  validation {
    condition = length(distinct([for rule in var.vulnerability_accept_rules : rule.id if rule != null])) == length(
      [for rule in var.vulnerability_accept_rules : rule.id if rule != null]
    )
    error_message = join("", [
      "vulnerability_accept_rules: no two rules may have the same id. Rules: ",
      join(", ", [
        for id in distinct([for rule in var.vulnerability_accept_rules : rule.id if rule != null]) : jsonencode(id)
        if length([for rule in var.vulnerability_accept_rules : rule.id if rule == null ? false : rule.id == id]) > 1
      ]),
      ".",
    ])
  }

  # The parameters of both inputs share one path, and a ticket cites a rule by its id alone.
  validation {
    condition = length(setintersection(
      [for rule in var.threat_accept_rules : rule.id if rule != null],
      [for rule in var.vulnerability_accept_rules : rule.id if rule != null],
    )) == 0
    error_message = join("", [
      "vulnerability_accept_rules: a rule's id must not be a threat_accept_rules rule's id too. Rules: ",
      join(", ", [
        for id in sort(setintersection(
          [for rule in var.threat_accept_rules : rule.id if rule != null],
          [for rule in var.vulnerability_accept_rules : rule.id if rule != null],
        )) : jsonencode(id)
      ]),
      ".",
    ])
  }

  # The id names the rule's parameter, and LoopProof's suppressions cite it.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        !can(regex("^[a-z0-9][a-z0-9-]{0,63}$", rule.id))
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule's id must be 1 to 64 lowercase letters, digits or hyphens, ",
      "starting with a letter or digit. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          !can(regex("^[a-z0-9][a-z0-9-]{0,63}$", rule.id))
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.reason == null ? true : trimspace(rule.reason) == ""
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule must give its reason. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.reason == null ? true : trimspace(rule.reason) == ""
        )
      ]),
      ".",
    ])
  }

  # A real date: formatdate refuses a day the month doesn't have.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.review_by == null ? true : !(
          can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", rule.review_by))
          && can(formatdate("YYYY", "${rule.review_by}T00:00:00Z"))
        )
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule's review_by must be a date, YYYY-MM-DD. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.review_by == null ? true : !(
            can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", rule.review_by))
            && can(formatdate("YYYY", "${rule.review_by}T00:00:00Z"))
          )
        )
      ]),
      ".",
    ])
  }

  # The format only: whether the register entry exists is LoopProof's to check, in Linear.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.decision_ref == null ? true : !can(
          regex("^[A-Z][A-Z0-9]*-[1-9][0-9]*$", rule.decision_ref)
        )
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule's decision_ref must be its register entry's Linear issue ",
      "identifier, such as SEC-42. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.decision_ref == null ? true : !can(
            regex("^[A-Z][A-Z0-9]*-[1-9][0-9]*$", rule.decision_ref)
          )
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        (rule.cves == null ? false : length(rule.cves) > 0) == (rule.package != null)
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule must name the cves it accepts or the package, not both. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          (rule.cves == null ? false : length(rule.cves) > 0) == (rule.package != null)
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.cves == null ? false : !alltrue([
          for cve in rule.cves : can(regex("^CVE-[0-9]{4}-[0-9]{4,}$", cve))
        ])
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: cves must be CVE identifiers, each in full, such as CVE-2024-12797. ",
      "Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.cves == null ? false : !alltrue([
            for cve in rule.cves : can(regex("^CVE-[0-9]{4}-[0-9]{4,}$", cve))
          ])
        )
      ]),
      ".",
    ])
  }

  # A source package's name and version, as the finding names them: no whitespace, no wildcard.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.package == null ? false : !(
          can(regex("^[^*\\s]+$", rule.package.name))
          && can(regex("^[^*\\s]+$", rule.package.version))
        )
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a package must have a name and a version, each in full. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.package == null ? false : !(
            can(regex("^[^*\\s]+$", rule.package.name))
            && can(regex("^[^*\\s]+$", rule.package.version))
          )
        )
      ]),
      ".",
    ])
  }

  # An account alone would accept everything in it, so it only narrows a rule (IH-60, 2026-11-04).
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.where == null ? true : !(
          (rule.where.resource_ids == null ? false : length(rule.where.resource_ids) > 0)
          || (rule.where.tags == null ? false : length(rule.where.tags) > 0)
          || (rule.where.image_repositories == null ? false : length(rule.where.image_repositories) > 0)
        )
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule's where must name resource_ids, tags or image_repositories; ",
      "accounts only narrows them. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? true : !(
            (rule.where.resource_ids == null ? false : length(rule.where.resource_ids) > 0)
            || (rule.where.tags == null ? false : length(rule.where.tags) > 0)
            || (rule.where.image_repositories == null ? false : length(rule.where.image_repositories) > 0)
          )
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.where == null ? false : (rule.where.accounts == null ? false : !alltrue([
          for account_id in rule.where.accounts : can(regex("^[0-9]{12}$", account_id))
        ]))
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: where.accounts must list 12-digit AWS account IDs. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? false : (rule.where.accounts == null ? false : !alltrue([
            for account_id in rule.where.accounts : can(regex("^[0-9]{12}$", account_id))
          ]))
        )
      ]),
      ".",
    ])
  }

  # Exact values: no wildcard, and no blank resource id, repository or tag key.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.where == null ? false : !alltrue(concat(
          [
            for value in(rule.where.resource_ids == null ? [] : rule.where.resource_ids) :
            can(regex("^[^*\\s]+$", value))
          ],
          [
            for value in(rule.where.image_repositories == null ? [] : rule.where.image_repositories) :
            can(regex("^[^*\\s]+$", value))
          ],
          [
            for key, value in(rule.where.tags == null ? {} : rule.where.tags) :
            can(regex("^[^*]*[^*\\s][^*]*$", key)) && can(regex("^[^*]*$", value))
          ],
        ))
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: where's resource_ids, image_repositories and tags must be values in ",
      "full. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.where == null ? false : !alltrue(concat(
            [
              for value in(rule.where.resource_ids == null ? [] : rule.where.resource_ids) :
              can(regex("^[^*\\s]+$", value))
            ],
            [
              for value in(rule.where.image_repositories == null ? [] : rule.where.image_repositories) :
              can(regex("^[^*\\s]+$", value))
            ],
            [
              for key, value in(rule.where.tags == null ? {} : rule.where.tags) :
              can(regex("^[^*]*[^*\\s][^*]*$", key)) && can(regex("^[^*]*$", value))
            ],
          ))
        )
      ]),
      ".",
    ])
  }

  # A value listed twice would publish other bytes than the same rule without the repeat.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        (rule.cves == null ? false : (
          length(distinct(rule.cves)) < length(rule.cves)
        ))
        || (rule.where == null ? false : rule.where.resource_ids == null ? false : (
          length(distinct(rule.where.resource_ids)) < length(rule.where.resource_ids)
        ))
        || (rule.where == null ? false : rule.where.image_repositories == null ? false : (
          length(distinct(rule.where.image_repositories)) < length(rule.where.image_repositories)
        ))
        || (rule.where == null ? false : rule.where.accounts == null ? false : (
          length(distinct(rule.where.accounts)) < length(rule.where.accounts)
        ))
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule must not list a value twice in cves, where.resource_ids, ",
      "where.image_repositories or where.accounts. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          (rule.cves == null ? false : (
            length(distinct(rule.cves)) < length(rule.cves)
          ))
          || (rule.where == null ? false : rule.where.resource_ids == null ? false : (
            length(distinct(rule.where.resource_ids)) < length(rule.where.resource_ids)
          ))
          || (rule.where == null ? false : rule.where.image_repositories == null ? false : (
            length(distinct(rule.where.image_repositories)) < length(rule.where.image_repositories)
          ))
          || (rule.where == null ? false : rule.where.accounts == null ? false : (
            length(distinct(rule.where.accounts)) < length(rule.where.accounts)
          ))
        )
      ]),
      ".",
    ])
  }
}
