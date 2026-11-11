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

    # What the rule accepts: cves, a package with its version, or both, the version then optional.
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
    The vulnerabilities you accept, each rule with its register entry in Linear. A rule names cves, and accepts
    them in any package; or a package with its version, and accepts every CVE in it; or both, and accepts its
    cves in that package only, at that version if it gives one: beside cves the version is optional. The package
    is the one LoopProof files the work under: an OS package's source package, such as openssh, never a binary
    package such as openssh-server, or a language package by its name. The module publishes each rule as JSON,
    with the kind vuln_remediation, in the SSM parameter /loopproof/<environment>/accept-rules/<id>, where
    LoopProof reads it with the connector role, and checks each rule's shape at plan. LoopProof judges what a
    rule means when it loads it, and checks its register entry. An id must not be a threat rule's too. See
    "Accepting risks" in the README.
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

  # A rule names cves, a package, or both, and then accepts a finding only when both hold (IH-60, 2026-11-08). An
  # empty list of cves names none.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        !(rule.cves == null ? false : length(rule.cves) > 0) && rule.package == null
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a rule must name the cves it accepts, a package, or both. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          !(rule.cves == null ? false : length(rule.cves) > 0) && rule.package == null
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

  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.package == null ? false : rule.package.name == null
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a package must have its name. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.package == null ? false : rule.package.name == null
        )
      ]),
      ".",
    ])
  }

  # A package named alone accepts every CVE in it, so it needs its version. Beside cves the version is optional:
  # a reason such as "we don't use openssh" holds at every version, and with a version required, each update that
  # doesn't fix the CVE would end the acceptance (IH-60, 2026-11-08).
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.package == null ? false : (
          rule.package.version == null && !(rule.cves == null ? false : length(rule.cves) > 0)
        )
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a package must have its version, unless the rule names cves. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.package == null ? false : (
            rule.package.version == null && !(rule.cves == null ? false : length(rule.cves) > 0)
          )
        )
      ]),
      ".",
    ])
  }

  # The package LoopProof files the work under, by its name and the version the rule gives, as LoopProof's work
  # grain holds them: no whitespace, no wildcard.
  validation {
    condition = alltrue([
      for rule in var.vulnerability_accept_rules : rule == null ? true : !(
        rule.package == null ? false : !alltrue([
          rule.package.name == null ? true : can(regex("^[^*\\s]+$", rule.package.name)),
          rule.package.version == null ? true : can(regex("^[^*\\s]+$", rule.package.version)),
        ])
      )
    ])
    error_message = join("", [
      "vulnerability_accept_rules: a package's name and version must be in full. Rules: ",
      join(", ", [
        for rule in var.vulnerability_accept_rules : jsonencode(rule.id) if rule == null ? false : (
          rule.package == null ? false : !alltrue([
            rule.package.name == null ? true : can(regex("^[^*\\s]+$", rule.package.name)),
            rule.package.version == null ? true : can(regex("^[^*\\s]+$", rule.package.version)),
          ])
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

variable "tenant_settings" {
  # Any shape, not an object type: Terraform drops an attribute an object type doesn't name, without an error, so
  # a misspelled setting would publish LoopProof's default in its place, a change of policy nobody wrote. The
  # checks below refuse any name the module doesn't know, at every level, and any value LoopProof's table refuses.
  # The names, the bounds and LoopProof's defaults are in locals.tf.
  type        = any
  description = <<-EOT
    Your settings in LoopProof, as your security policy states them: sla_target_days, the days from a work item's
    start to its due date, by kind (threat_response, vuln_remediation) and severity (critical, which covers Fatal,
    high, medium, low); thresholds, by kind, the lowest severity that opens a work item ("High" or "Medium" for
    threat_response, "High" for vuln_remediation); quiet_window_days, how long after a work item closes a returning
    finding reopens it rather than open a new one; ticket_budget_per_hour, how many tickets LoopProof files in any
    hour; and review_due_before_days, how long before an accept rule's review_by date it is due for review. A
    setting left out is LoopProof's default: SLA targets of 7, 14, 30 and 90 days for both kinds, both thresholds
    "High", a quiet window of 14 days, 20 tickets an hour, and review due 14 days before. Days are whole days, and
    no SLA target may be longer than a less severe one's. The module refuses a setting it doesn't know, such as a
    misspelled one, and publishes every setting as JSON in the SSM parameter /loopproof/<environment>/tenant-settings,
    where LoopProof reads it with the connector role within 15 minutes and records each change as a version. A
    change applies to work items that open after LoopProof reads it. See "Your settings in LoopProof" in the README.
  EOT
  default     = {}
  nullable    = false

  # Each message names the input and the settings it refuses. A check that finds what an earlier one refuses, such
  # as an attribute of something that isn't an object, passes, so that each mistake gets one message.
  validation {
    condition     = can(keys(var.tenant_settings))
    error_message = "tenant_settings must be an object of settings."
  }

  validation {
    condition = length([
      for path, value in {
        "sla_target_days"                  = try(var.tenant_settings.sla_target_days, null)
        "sla_target_days.threat_response"  = try(var.tenant_settings.sla_target_days.threat_response, null)
        "sla_target_days.vuln_remediation" = try(var.tenant_settings.sla_target_days.vuln_remediation, null)
        "thresholds"                       = try(var.tenant_settings.thresholds, null)
      } : path if value == null ? false : !can(keys(value))
    ]) == 0
    error_message = join("", [
      "tenant_settings: sla_target_days, each kind in it, and thresholds must be objects. Settings: ",
      join(", ", [
        for path, value in {
          "sla_target_days"                  = try(var.tenant_settings.sla_target_days, null)
          "sla_target_days.threat_response"  = try(var.tenant_settings.sla_target_days.threat_response, null)
          "sla_target_days.vuln_remediation" = try(var.tenant_settings.sla_target_days.vuln_remediation, null)
          "thresholds"                       = try(var.tenant_settings.thresholds, null)
        } : path if value == null ? false : !can(keys(value))
      ]),
      ".",
    ])
  }

  # A misspelled setting is refused, never published as LoopProof's default.
  validation {
    condition = length(concat(
      [for name in try(keys(var.tenant_settings), []) : name if !contains(local.tenant_setting_names, name)],
      [
        for kind in try(keys(var.tenant_settings.sla_target_days), []) : kind
        if !contains(local.tenant_settings_kinds, kind)
      ],
      flatten([
        for kind in local.tenant_settings_kinds : [
          for severity in try(keys(var.tenant_settings.sla_target_days[kind]), []) : severity
          if !contains(local.tenant_settings_severities, severity)
        ]
      ]),
      [
        for kind in try(keys(var.tenant_settings.thresholds), []) : kind
        if !contains(local.tenant_settings_kinds, kind)
      ],
    )) == 0
    error_message = join("", [
      "tenant_settings: unknown setting. The settings are sla_target_days.<kind>.<severity>, thresholds.<kind>, ",
      "quiet_window_days, ticket_budget_per_hour and review_due_before_days, where a kind is threat_response or ",
      "vuln_remediation, and a severity critical, high, medium or low, critical covering Fatal. Settings: ",
      join(", ", sort(concat(
        [for name in try(keys(var.tenant_settings), []) : name if !contains(local.tenant_setting_names, name)],
        [
          for kind in try(keys(var.tenant_settings.sla_target_days), []) : "sla_target_days.${kind}"
          if !contains(local.tenant_settings_kinds, kind)
        ],
        flatten([
          for kind in local.tenant_settings_kinds : [
            for severity in try(keys(var.tenant_settings.sla_target_days[kind]), []) :
            "sla_target_days.${kind}.${severity}" if !contains(local.tenant_settings_severities, severity)
          ]
        ]),
        [
          for kind in try(keys(var.tenant_settings.thresholds), []) : "thresholds.${kind}"
          if !contains(local.tenant_settings_kinds, kind)
        ],
      ))),
      ".",
    ])
  }

  # Whole days: a tenant's policy states its targets in days, and a whole number of days is a whole number of
  # hours, the unit of LoopProof's grace windows, which it compares with the targets.
  validation {
    condition = length(flatten([
      for kind in local.tenant_settings_kinds : [
        for index, days in [
          for severity in local.tenant_settings_severities :
          try(var.tenant_settings.sla_target_days[kind][severity], null)
          ] : index if days == null ? false : !try(
          floor(tonumber(days)) == tonumber(days)
          && tonumber(days) >= 1 && tonumber(days) <= local.tenant_settings_max_days,
          false
        )
      ]
    ])) == 0
    error_message = join("", [
      "tenant_settings: an SLA target must be a whole number of days from 1 to ${local.tenant_settings_max_days}. ",
      "Settings: ",
      join(", ", flatten([
        for kind in local.tenant_settings_kinds : [
          for index, days in [
            for severity in local.tenant_settings_severities :
            try(var.tenant_settings.sla_target_days[kind][severity], null)
            ] : "sla_target_days.${kind}.${local.tenant_settings_severities[index]}" if days == null ? false : !try(
            floor(tonumber(days)) == tonumber(days)
            && tonumber(days) >= 1 && tonumber(days) <= local.tenant_settings_max_days,
            false
          )
        ]
      ])),
      ".",
    ])
  }

  # No more severe finding gets longer than a less severe one, counting LoopProof's default for a target left
  # out: a policy that does has two targets swapped. Equal targets are allowed. A kind with a target the check
  # above refuses (null here) is left to it.
  validation {
    condition = alltrue([
      for kind, targets in {
        for kind in local.tenant_settings_kinds : kind => [
          for index, days in [
            for severity in local.tenant_settings_severities :
            try(var.tenant_settings.sla_target_days[kind][severity], null)
            ] : days == null ? local.tenant_settings_defaults.sla_target_days[kind][
            local.tenant_settings_severities[index]
            ] : try(
            floor(tonumber(days)) == tonumber(days)
            && tonumber(days) >= 1 && tonumber(days) <= local.tenant_settings_max_days ? tonumber(days) : null,
            null
          )
        ]
        } : anytrue([for days in targets : days == null]) ? true : alltrue([
          for index in range(length(targets) - 1) : targets[index] <= targets[index + 1]
      ])
    ])
    error_message = join("", [
      "tenant_settings: an SLA target must not be longer than a less severe one's, counting LoopProof's default ",
      "for a target left out. Settings: ",
      join(", ", [
        for kind, targets in {
          for kind in local.tenant_settings_kinds : kind => [
            for index, days in [
              for severity in local.tenant_settings_severities :
              try(var.tenant_settings.sla_target_days[kind][severity], null)
              ] : days == null ? local.tenant_settings_defaults.sla_target_days[kind][
              local.tenant_settings_severities[index]
              ] : try(
              floor(tonumber(days)) == tonumber(days)
              && tonumber(days) >= 1 && tonumber(days) <= local.tenant_settings_max_days ? tonumber(days) : null,
              null
            )
          ]
          } : join("", [
            "sla_target_days.${kind} (",
            join(", ", [
              for index, days in targets : "${local.tenant_settings_severities[index]} ${days}"
            ]),
            ")",
            ]) if anytrue([for days in targets : days == null]) ? false : !alltrue([
            for index in range(length(targets) - 1) : targets[index] <= targets[index + 1]
        ])
      ]),
      ".",
    ])
  }

  # LoopProof's table allows these alone (Aleks, 2026-10-27): threats from High, or from Medium, since the
  # connector forwards GuardDuty's findings at every severity; vulnerabilities from High.
  validation {
    condition = alltrue([
      for kind, allowed in local.tenant_settings_thresholds : (
        try(var.tenant_settings.thresholds[kind], null) == null ? true : try(
          contains(allowed, var.tenant_settings.thresholds[kind]), false
        )
      )
    ])
    error_message = join("", [
      "tenant_settings: a threshold must be High or Medium for threat_response, and High for vuln_remediation, ",
      "capitalized as Security Hub writes them. Settings: ",
      join(", ", [
        for kind, allowed in local.tenant_settings_thresholds : "thresholds.${kind}"
        if !(
          try(var.tenant_settings.thresholds[kind], null) == null ? true : try(
            contains(allowed, var.tenant_settings.thresholds[kind]), false
          )
        )
      ]),
      ".",
    ])
  }

  validation {
    condition = alltrue([
      for value in [try(var.tenant_settings.quiet_window_days, null)] : value == null ? true : try(
        floor(tonumber(value)) == tonumber(value)
        && tonumber(value) >= 0 && tonumber(value) <= local.tenant_settings_max_days,
        false
      )
    ])
    error_message = join("", [
      "tenant_settings: quiet_window_days must be a whole number of days from 0 to ",
      "${local.tenant_settings_max_days}.",
    ])
  }

  validation {
    condition = alltrue([
      for value in [try(var.tenant_settings.ticket_budget_per_hour, null)] : value == null ? true : try(
        floor(tonumber(value)) == tonumber(value)
        && tonumber(value) >= 1 && tonumber(value) <= local.tenant_settings_max_budget,
        false
      )
    ])
    error_message = join("", [
      "tenant_settings: ticket_budget_per_hour must be a whole number from 1 to ",
      "${local.tenant_settings_max_budget}.",
    ])
  }

  validation {
    condition = alltrue([
      for value in [try(var.tenant_settings.review_due_before_days, null)] : value == null ? true : try(
        floor(tonumber(value)) == tonumber(value)
        && tonumber(value) >= 1 && tonumber(value) <= local.tenant_settings_max_days,
        false
      )
    ])
    error_message = join("", [
      "tenant_settings: review_due_before_days must be a whole number of days from 1 to ",
      "${local.tenant_settings_max_days}.",
    ])
  }
}
