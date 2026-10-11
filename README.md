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
  LoopProof's event bus;
* a one-time call that reports the role's ARN to LoopProof, so onboarding needs no copy and paste.

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
* Forwarder role that may only `events:PutEvents` on LoopProof's bus
* Self-registration through the `hashicorp/http` data source, with the token kept out of plan output
* Input validation for account ID, ExternalIds, bus ARN, registration URL, token and severities

## Quick Start

LoopProof's onboarding generates the module call for you, once, at sign-up. It looks like this:

```hcl
module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "0.0.0"

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

With `registration_token` set, the module POSTs the role's ARN to `registration_url` once the role exists, with
`Authorization: Bearer <token>`. The token comes from LoopProof's onboarding and is valid for 24 hours.

* Set it for the first apply, then remove it. When it's `null`, the module makes no call.
* The call is a data source, so Terraform makes it on **every** plan while the token is set, including the plan of
  a `destroy`. LoopProof answers `200` to a repeat of the same token with the same ARN, so that is harmless, but a
  token LoopProof no longer accepts will fail the plan.
* Any answer but `200` fails the apply with the role's ARN and a message to paste it into LoopProof instead. The
  `role_arn` output has it too. The ARN is only a hint: LoopProof proves the account later by assuming the role.

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
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |
| <a name="requirement_http"></a> [http](#requirement\_http) | ~> 3.5 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 6.0 |
| <a name="provider_http"></a> [http](#provider\_http) | ~> 3.5 |

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
| [aws_iam_role_policy.forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.connector_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.forwarder_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.forwarder_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [http_http.registration](https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_control_plane_account_id"></a> [control\_plane\_account\_id](#input\_control\_plane\_account\_id) | ID of LoopProof's control-plane AWS account for this environment. Twelve digits. | `string` | n/a | yes |
| <a name="input_environment"></a> [environment](#input\_environment) | LoopProof's environment, such as staging or production. It names the connector role<br/>(loopproof-<environment>-connector) and selects the control-plane roles allowed to assume it<br/>(loopproof-<environment>-*). | `string` | n/a | yes |
| <a name="input_event_bus_arn"></a> [event\_bus\_arn](#input\_event\_bus\_arn) | ARN of LoopProof's control-plane EventBridge bus that receives the forwarded findings. | `string` | n/a | yes |
| <a name="input_external_ids"></a> [external\_ids](#input\_external\_ids) | ExternalIds that LoopProof presents when it assumes the connector role. One value normally,<br/>two during a rotation. LoopProof generates them; feed them from your own parameter store and<br/>never commit them. | `list(string)` | n/a | yes |
| <a name="input_registration_token"></a> [registration\_token](#input\_registration\_token) | One-time registration token (lprt\_...) from LoopProof's onboarding, valid for 24 hours.<br/>When set, the module reports the connector role's ARN to registration\_url.<br/>Set it for the first apply and remove it afterwards. When null, the module makes no call. | `string` | `null` | no |
| <a name="input_registration_url"></a> [registration\_url](#input\_registration\_url) | LoopProof's connector registration endpoint, such as<br/>https://api.staging.loopproof.ai/connector/registrations. It must use https://;<br/>http:// is accepted only for 127.0.0.1 and localhost, for tests. | `string` | n/a | yes |
| <a name="input_severities"></a> [severities](#input\_severities) | Severities of the Security Hub findings to forward, as they appear in the OCSF severity field:<br/>Unknown, Informational, Low, Medium, High, Critical, Fatal or Other. | `list(string)` | <pre>[<br/>  "High",<br/>  "Critical",<br/>  "Fatal"<br/>]</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_event_rule_arn"></a> [event\_rule\_arn](#output\_event\_rule\_arn) | ARN of the EventBridge rule that forwards Security Hub findings to LoopProof. |
| <a name="output_registered"></a> [registered](#output\_registered) | true once LoopProof accepted the registration; null when registration\_token is null. |
| <a name="output_role_arn"></a> [role\_arn](#output\_role\_arn) | ARN of the connector role. Paste it into LoopProof's onboarding if the registration call failed. |
| <a name="output_role_name"></a> [role\_name](#output\_role\_name) | Name of the connector role, loopproof-<environment>-connector. |
<!-- END_TF_DOCS -->

## Examples

See [examples/](examples/) for a working configuration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
