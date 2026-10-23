# terraform-aws-loopproof-connector

[![Need Help?](https://img.shields.io/badge/Need%20Help%3F-Contact%20Us-0066CC)](https://infrahouse.com/contact)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://infrahouse.github.io/terraform-aws-loopproof-connector/)
[![Registry](https://img.shields.io/badge/Terraform-Registry-purple?logo=terraform)](https://registry.terraform.io/modules/infrahouse/loopproof-connector/aws/latest)
[![Release](https://img.shields.io/github/release/infrahouse/terraform-aws-loopproof-connector.svg)](https://github.com/infrahouse/terraform-aws-loopproof-connector/releases/latest)
[![AWS Security Hub](https://img.shields.io/badge/AWS-Security%20Hub-orange?logo=amazonwebservices)](https://aws.amazon.com/security-hub/)
[![AWS EventBridge](https://img.shields.io/badge/AWS-EventBridge-orange?logo=amazonwebservices)](https://aws.amazon.com/eventbridge/)
[![Security](https://img.shields.io/github/actions/workflow/status/infrahouse/terraform-aws-loopproof-connector/vuln-scanner-pr.yml?label=Security)](https://github.com/infrahouse/terraform-aws-loopproof-connector/actions/workflows/vuln-scanner-pr.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

The LoopProof connector. LoopProof turns your AWS Security Hub findings into Linear tickets; this module gives it
the access it needs in your account, and nothing more:

* a cross-account IAM role that LoopProof's control plane assumes, with an ExternalId, to read findings and set
  their status and comment;
* an EventBridge rule that forwards Security Hub's "Findings Imported V2" events of the severities you choose to
  LoopProof's event bus, except the findings of the accounts you exclude;
* an SSM parameter that tells LoopProof which accounts you exclude;
* a one-time call that reports the role's ARN and the Region to LoopProof, so onboarding needs no copy and paste.

## Why This Module?

Connecting a third-party service to Security Hub usually means a hand-made role with broad Security Hub
permissions, a long-lived ExternalId in a tfvars file, and an ARN pasted into a web form. This module:

* trusts only LoopProof's own roles for your environment, by role name and ExternalId;
* grants the two IAM actions the Security Hub v2 APIs need, and denies any update but status and comment;
* treats the ExternalId as a credential: it's a sensitive input, masked in plan output, and never written to an
  output, a tag or a description;
* rotates the ExternalId without a single failed `AssumeRole`;
* registers itself, with no binary needed on the machine that runs Terraform.

## Features

* Connector role `loopproof-<environment>-connector`, assumable only by the control plane's
  `loopproof-<environment>-*` roles presenting one of one or two ExternalIds
* Least-privilege permissions: `securityhub:GetFindings` and `securityhub:BatchUpdateFindings`, the latter confined
  to the status and the comment
* Forwarding of new, updated and closed findings by OCSF severity, to a bus in another account and Region
* Account exclusion: the findings of the accounts in `excluded_accounts` never leave your account, and the list is
  published in SSM for LoopProof to read
* Forwarder role that may only `events:PutEvents` on LoopProof's bus
* Self-registration through the `hashicorp/http` data source, with the token kept out of plan output
* Input validation for account ID, ExternalIds, bus ARN, registration URL, token, severities and excluded accounts

## Quick Start

LoopProof's onboarding generates the module call for you, once, at sign-up. It looks like this:

```hcl
module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "0.3.0"

  environment              = "production"
  control_plane_account_id = "123456789012"
  external_ids             = [var.loopproof_external_id]
  event_bus_arn            = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url         = "https://api.loopproof.ai/connector/registrations"
  registration_token       = var.loopproof_registration_token
}

variable "loopproof_external_id" {
  type      = string
  sensitive = true
}

variable "loopproof_registration_token" {
  type      = string
  sensitive = true
  default   = null
}
```

### Where to install it

Install it in the account where Security Hub collects your findings, in Security Hub's **home Region**:

* with AWS Control Tower or an AWS Organization, that's the Security Hub delegated administrator, usually the Audit
  account;
* otherwise, it's your single account.

There, Security Hub's event feed includes the findings of the member accounts and of the linked Regions.

### The ExternalId is a credential

LoopProof generates the ExternalId; you only feed it in. Keep it in your own parameter store, such as AWS Systems
Manager Parameter Store or Secrets Manager, and pass it as a sensitive variable. Never commit it.

```hcl
data "aws_ssm_parameter" "loopproof_external_id" {
  name = "/loopproof/external-id"
}

module "loopproof_connector" {
  # ...
  external_ids = [data.aws_ssm_parameter.loopproof_external_id.value]
}
```

The module never writes the ExternalId to an output, a tag, a description or a log, and the plan shows the trust
policy as `(sensitive value)`. Like every input, it is stored in the Terraform state, so protect the state as usual.

### Rotating the ExternalId

1. Apply with both values: `external_ids = [old, new]`. LoopProof's calls keep working with the old one.
2. Wait at least 10 minutes, then tell LoopProof to switch; it now presents the new one.
3. Apply with the new one only: `external_ids = [new]`.

IAM applies a trust policy change gradually. For a few minutes after step 1, some STS requests still see the old
policy and refuse the new value, while the old value keeps working throughout. That's why step 2 waits, and why the
old value stays listed until LoopProof has switched.

### Registration

With `registration_token` set, the module POSTs the role's ARN and the Region it's applied in to `registration_url`
once the role exists, with `Authorization: Bearer <token>`. The token comes from LoopProof's onboarding and is valid
for 24 hours.

LoopProof reads your Security Hub findings in that Region, the AWS provider's Region where you apply the module:
Security Hub's home Region, if you install it [where it belongs](#where-to-install-it). An IAM role ARN names no
Region, so LoopProof can't learn it from the ARN.

* Set it for the first apply, then remove it. When it's `null`, the module makes no call.
* The call is a data source, so Terraform makes it on **every** plan while the token is set, including the plan of
  a `destroy`. LoopProof answers `200` to a repeat of the same token with the same ARN, so that is harmless, but a
  token LoopProof no longer accepts will fail the plan.
* Any answer but `200` fails the apply with the role's ARN, the Region and a message to paste them into LoopProof
  instead. The `role_arn` and `region` outputs have them too. The ARN is only a hint: LoopProof proves the account
  later by assuming the role.

### Excluding accounts

To keep an account out of LoopProof, such as an account outside your audit scope or a decommissioned one, list it in
`excluded_accounts`:

```hcl
module "loopproof_connector" {
  # ...
  excluded_accounts = ["111122223333"]
}
```

* The forwarding rule drops the findings of those accounts, by the finding's account (`cloud.account.uid`), so they
  never leave your account.
* The module publishes the list, sorted, as JSON in the SSM `String` parameter
  `/loopproof/<environment>/excluded-accounts`, in the module's Region; the `excluded_accounts_parameter` output
  names it. The parameter exists, holding `[]`, when you exclude nothing. LoopProof reads it with the connector role
  when it proves your account, and daily after, to keep those accounts out of its scope. The role may read that
  parameter and nothing else in SSM.
* A change takes effect on the next apply. Make it as you change the rest of your Terraform, by pull request;
  LoopProof doesn't ask why.
* IAM can't limit `securityhub:GetFindings` to some accounts, so the connector role can still read an excluded
  account's findings through `GetFindingsV2`. The list is how LoopProof knows to leave them out.
* EventBridge limits a rule's pattern to 4096 characters, which holds about 250 excluded accounts.

### Events are refused until LoopProof proves the account

Until LoopProof has proven your account (a later onboarding step, in which it assumes the role), its bus refuses
your events. EventBridge doesn't retry a permission error; without a dead-letter queue, it drops the event and
counts it in the rule's `FailedInvocations` metric. Nothing is lost: once the account is proven, LoopProof imports
your findings' history through the connector role. You don't need to debug those failures.

## Documentation

Full documentation is at [infrahouse.github.io/terraform-aws-loopproof-connector](https://infrahouse.github.io/terraform-aws-loopproof-connector/):

* [Getting Started](https://infrahouse.github.io/terraform-aws-loopproof-connector/getting-started/)
* [Architecture](https://infrahouse.github.io/terraform-aws-loopproof-connector/architecture/)
* [Configuration](https://infrahouse.github.io/terraform-aws-loopproof-connector/configuration/)
* [Security](https://infrahouse.github.io/terraform-aws-loopproof-connector/security/)
* [Troubleshooting](https://infrahouse.github.io/terraform-aws-loopproof-connector/troubleshooting/)

## Requirements

* Terraform `~> 1.5`
* AWS provider `~> 6.0`
* HTTP provider `~> 3.5`
* Security Hub (the OCSF-based version, not Security Hub CSPM alone) enabled in the account and Region

## Usage

<!-- BEGIN_TF_DOCS -->

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.10 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.findings](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.control_plane](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_iam_role.connector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.connector](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.connector_excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_ssm_parameter.excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [terraform_data.registration](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.connector_excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.forwarder_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.forwarder_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_ssm_parameter.external_ids](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_control_plane_account_id"></a> [control\_plane\_account\_id](#input\_control\_plane\_account\_id) | ID of LoopProof's control-plane AWS account for this environment. Twelve digits. | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | LoopProof's environment, such as staging or production. It names the connector role<br/>(loopproof-<environment>-connector) and selects the control-plane roles allowed to assume it<br/>(loopproof-<environment>-*). | `string` | n/a | yes |
| <a name="input_event_bus_arn"></a> [event\_bus\_arn](#input\_event\_bus\_arn) | ARN of LoopProof's control-plane EventBridge bus that receives the forwarded findings. | `string` | n/a | yes |
| <a name="input_excluded_accounts"></a> [excluded\_accounts](#input\_excluded\_accounts) | IDs of the AWS accounts you exclude from LoopProof, such as an account outside your audit scope or a<br/>decommissioned one. The forwarding rule drops their findings, so they never leave this account, and the<br/>module publishes the list in the SSM parameter /loopproof/<environment>/excluded-accounts, where LoopProof<br/>reads it. A change takes effect on the next apply. | `list(string)` | `[]` | no |
| <a name="input_external_ids_parameter_arn"></a> [external\_ids\_parameter\_arn](#input\_external\_ids\_parameter\_arn) | ARN of the SSM SecureString parameter that holds the ExternalIds LoopProof presents when it assumes the<br/>connector role, as a JSON list: one value, or two during a rotation. Pass the ARN of the parameter your<br/>root creates, aws\_ssm\_parameter.<name>.arn, never the value. The module reads it with the AWS<br/>provider's credentials. Until you fill it, it holds the placeholder "unset", and the apply stops there. | `string` | n/a | yes |
| <a name="input_registration_token_parameter_arn"></a> [registration\_token\_parameter\_arn](#input\_registration\_token\_parameter\_arn) | ARN of the SSM SecureString parameter that holds the registration token (lprt\_...) from LoopProof's<br/>onboarding. Pass the ARN of the parameter your root creates, aws\_ssm\_parameter.<name>.arn, never the<br/>value. The module reads it as an ephemeral value, so the token is in neither the plan nor the state, and<br/>uses it once: on the apply that creates the connector role, it reports the role's ARN and the Region to<br/>registration\_url. | `string` | n/a | yes |
| <a name="input_registration_url"></a> [registration\_url](#input\_registration\_url) | LoopProof's connector registration endpoint, such as<br/>https://api.staging.loopproof.ai/connector/registrations. The module POSTs the connector<br/>role's ARN and the Region it is applied in there. It must use https://;<br/>http:// is accepted only for 127.0.0.1 and localhost, for tests. | `string` | n/a | yes |
| <a name="input_severities"></a> [severities](#input\_severities) | Severities of the Security Hub findings to forward, as they appear in the OCSF severity field:<br/>Unknown, Informational, Low, Medium, High, Critical, Fatal or Other. | `list(string)` | <pre>[<br/>  "High",<br/>  "Critical",<br/>  "Fatal"<br/>]</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_event_rule_arn"></a> [event\_rule\_arn](#output\_event\_rule\_arn) | ARN of the EventBridge rule that forwards Security Hub findings to LoopProof. |
| <a name="output_excluded_accounts_parameter"></a> [excluded\_accounts\_parameter](#output\_excluded\_accounts\_parameter) | Name of the SSM parameter that publishes excluded\_accounts to LoopProof, /loopproof/<environment>/excluded-accounts. |
| <a name="output_region"></a> [region](#output\_region) | Region the module is applied in, where LoopProof reads the Security Hub findings. Paste it into LoopProof's<br/>onboarding with role\_arn if the registration call can't succeed. |
| <a name="output_role_arn"></a> [role\_arn](#output\_role\_arn) | ARN of the connector role. Paste it into LoopProof's onboarding, with region, if the registration call can't<br/>succeed, such as from a machine that can't reach LoopProof. |
| <a name="output_role_name"></a> [role\_name](#output\_role\_name) | Name of the connector role, loopproof-<environment>-connector. |
<!-- END_TF_DOCS -->

## Examples

See [examples/](examples/) for a working configuration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
