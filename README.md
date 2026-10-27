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
  their status and comment, and to read the tags of the resources they relate to: your ECR repositories' tags, and
  queries of your Config aggregators, which return any configuration an aggregator holds, not only tags;
* an EventBridge rule that forwards Security Hub's "Findings Imported V2" events of the severities you choose to
  LoopProof's event bus, except the findings of the accounts you exclude;
* an SSM parameter that tells LoopProof which accounts you exclude;
* one call, on the apply that creates the role, that reports the role's ARN and the Region to LoopProof, so
  onboarding needs no copy and paste.

## Why This Module?

Connecting a third-party service to Security Hub usually means a hand-made role with broad Security Hub
permissions, a long-lived ExternalId in a tfvars file, and an ARN pasted into a web form. This module:

* trusts only LoopProof's own roles for your environment, by role name and ExternalId;
* grants the two IAM actions the Security Hub v2 APIs need, and denies any update but status and comment;
* reads your ECR repositories' tags, and nothing else of ECR, and queries your Config aggregators, such as AWS Control
  Tower's, whose answers can hold any configuration an aggregator holds;
* treats the ExternalId and the registration token as credentials: it reads both from SSM SecureString parameters
  in your account, never from its inputs, so neither is ever in your code or a tfvars file, and the token is in
  neither the plan nor the state;
* rotates the ExternalId without a single failed `AssumeRole`, and without a change to your Terraform;
* registers itself once, at apply, and never calls LoopProof on a plan.

## Features

* Connector role `loopproof-<environment>-connector`, assumable only by the control plane's
  `loopproof-<environment>-*` roles presenting one of one or two ExternalIds
* Least-privilege permissions: `securityhub:GetFindings` and `securityhub:BatchUpdateFindings`, the latter confined
  to the status and the comment
* Resource tags: `ecr:ListTagsForResource` on your account's repositories, and `config:SelectAggregateResourceConfig`
  on your account's Config aggregators in the module's Region, such as AWS Control Tower's, which returns any
  configuration they hold, not only tags
* Forwarding of new, updated and closed findings by OCSF severity, to a bus in another account and Region
* Account exclusion: the findings of the accounts in `excluded_accounts` never leave your account, and the list is
  published in SSM for LoopProof to read
* Forwarder role that may only `events:PutEvents` on LoopProof's bus
* The ExternalIds read from an SSM parameter, checked before use; the registration token read as an ephemeral value
* Self-registration once, at apply, with `curl`, retried on connection errors and 5xx answers only
* Input validation for account ID, parameter ARNs, bus ARN, registration URL, severities and excluded accounts

## Quick Start

LoopProof's onboarding shows you the ExternalId and a registration token, once, and generates the Terraform for
you, in two parts that go in the same root. It looks like this.

**Part 1, the values.** Two SSM SecureString parameters in the account and Region where you install the connector,
created with the placeholder `unset`. The placeholder is write-only (`value_wo`), so Terraform never stores or
compares the value, and never writes it again: you fill the parameters yourself, below. Write-only arguments need
Terraform 1.11.

```hcl
resource "aws_ssm_parameter" "loopproof_external_ids" {
  name             = "/loopproof/production/external-ids"
  description      = "ExternalIds that LoopProof presents to the connector role, as a JSON list."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

resource "aws_ssm_parameter" "loopproof_registration_token" {
  name             = "/loopproof/production/registration-token"
  description      = "Registration token from LoopProof's onboarding."
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}
```

**Part 2, the connector.** The module takes the two parameters' ARNs, never their values, and reads them itself
with the AWS provider's credentials:

```hcl
module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "1.0.1"

  environment                      = "production"
  control_plane_account_id         = "123456789012"
  external_ids_parameter_arn       = aws_ssm_parameter.loopproof_external_ids.arn
  registration_token_parameter_arn = aws_ssm_parameter.loopproof_registration_token.arn
  event_bus_arn                    = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url                 = "https://api.loopproof.ai/connector/registrations"
}
```

If you manage parameters another way, skip Part 1 and pass the ARNs of your own SecureString parameters as strings.

### Installing: apply, fill, apply

1. **`terraform apply`.** It creates the two parameters. The module waits for them, reads the placeholder, and
   stops with an error that names the parameter to fill. Nothing else is created yet.
2. **Fill both parameters**, with the commands below, in the same account and Region.
3. **`terraform apply`** again. It creates the connector and registers the role with LoopProof.

`terraform apply -target` on the two parameters, then a plain apply, does the same without the first error.

### Filling the parameters

Each command asks for the value without echoing it, and hands it to the AWS CLI on its standard input, so it is on
no command line and in no shell history. Use credentials and a Region for the account where you install the
connector, and the parameter names from Part 1.

The ExternalIds, as a JSON list:

```bash
printf 'ExternalId: ' >&2; stty -echo; read -r value; stty echo; printf '\n' >&2
printf '["%s"]' "$value" | aws ssm put-parameter --overwrite --type SecureString \
  --name /loopproof/production/external-ids --value file:///dev/stdin; unset value
```

The registration token:

```bash
printf 'Registration token: ' >&2; stty -echo; read -r value; stty echo; printf '\n' >&2
printf '%s' "$value" | aws ssm put-parameter --overwrite --type SecureString \
  --name /loopproof/production/registration-token --value file:///dev/stdin; unset value
```

If Part 1 gives the parameters a customer-managed KMS key (`key_id`), add `--key-id` with that key to both
commands: without it, SSM re-encrypts the value with the default key `aws/ssm`.

### Where to install it

Install it in the account where Security Hub collects your findings, in Security Hub's **home Region**:

* with AWS Control Tower or an AWS Organization, that's the Security Hub delegated administrator, usually the Audit
  account;
* otherwise, it's your single account.

There, Security Hub's event feed includes the findings of the member accounts and of the linked Regions.

### Permissions for whoever applies it

Besides managing IAM roles, EventBridge rules and SSM parameters:

* `ssm:GetParameter` on `/loopproof/<environment>/*`: the module reads both parameters on every plan and apply;
* `kms:Decrypt` on the key, if Part 1 gives the parameters a customer-managed key instead of the default
  `aws/ssm`, whose key policy already allows it to the account's principals;
* `curl` 7.76.0 or later on the machine that runs Terraform, Linux or macOS, with HTTPS access to
  `registration_url`. Windows isn't supported.

The fill commands need `ssm:PutParameter`, and with a customer-managed key `kms:Encrypt` and `kms:GenerateDataKey`.

### The values are credentials

LoopProof generates the ExternalId and the token, and treats both as credentials; so does the module:

* neither is an input, so neither is ever in your code or a tfvars file;
* the ExternalIds are checked before they're used: the placeholder, or a value that isn't a JSON list of one or two
  ExternalIds, stops the run with a message that names the parameter and never shows the value;
* the plan shows the connector role's trust policy, which holds the ExternalIds, as `(sensitive value)`;
* the token is read as an ephemeral value: it is in neither the plan nor the state, and reaches `curl` through its
  environment and standard input, never a command line;
* no output, tag or description holds either.

The ExternalIds are in the state, and so in any saved plan file (`terraform plan -out`), in the module's read and
the trust policy, and readable in the role by anyone in your account allowed `iam:GetRole`. That is unavoidable, and
inside your account; protect saved plans, such as CI artifacts, as you protect the state.

At `TF_LOG=DEBUG` the AWS provider logs the responses of its AWS calls but an ephemeral read's, so a debug log of
this root holds both values: refreshing Part 1's parameters reads them decrypted, and the module's read of the
ExternalIds and the role's trust policy show the ExternalIds. Treat such a log as a secret.

`terraform destroy` deletes the parameters with their values, which is right for an uninstall; know it before you
destroy the root for another reason.

### Rotating the ExternalId

1. Put both values in the parameter, `["<old>","<new>"]`, and apply. LoopProof's calls keep working with the old
   one.
2. Wait at least 10 minutes, then tell LoopProof to switch; it now presents the new one.
3. Put the new one only, `["<new>"]`, and apply.

Your Terraform doesn't change: each apply reads the parameter and updates the trust policy in place. IAM applies a
trust policy change gradually. For a few minutes after step 1, some STS requests still see the old policy and refuse
the new value, while the old value keeps working throughout. That's why step 2 waits, and why the old value stays
listed until LoopProof has switched.

### Registration

On the apply that creates the connector role, the module POSTs the role's ARN and the Region it's applied in to
`registration_url`, once, with `curl`, and `Authorization: Bearer <token>` from the token parameter. Later plans and
applies make no call.

LoopProof reads your Security Hub findings in that Region, the AWS provider's Region where you apply the module:
Security Hub's home Region, if you install it [where it belongs](#where-to-install-it). An IAM role ARN names no
Region, so LoopProof can't learn it from the ARN.

* **A refused call** (HTTP 4xx, such as an expired token) fails the apply. The error shows LoopProof's answer and
  says to get a new registration token in LoopProof and put it in the token parameter. 4xx answers aren't retried.
* **Where a new token comes from** depends on whether LoopProof has proven your account, a later onboarding step in
  which it assumes the role. The module can't tell, so the error names both places:
  * before, LoopProof's onboarding gives you one;
  * after, an admin of your tenant mints one on LoopProof's Settings page, with "Mint a new registration token". A
    minted token registers only the role your tenant already has: LoopProof answers `200` and changes nothing.

  A new token replaces the one before it, which stops working at once, the one in your parameter included.
* **The paste.** The error also gives the role's ARN and the Region. Before LoopProof has proven your account, you
  can paste them into LoopProof's onboarding instead. After, LoopProof takes no paste.
* **Once the new token is in the parameter, apply again.** The failed registration is tainted, so the plain apply
  registers by itself.
* **Connection errors and 5xx answers** are retried, four attempts in all, before the apply fails the same way.
* **The call runs again** when the role is replaced, and with `terraform apply -replace` on
  `module.<name>.terraform_data.registration`. LoopProof answers `200` for a role it already has.
* While the call runs, Terraform shows its output as `(output suppressed due to ephemeral value in config)`, because
  the token is in its environment; when it fails, the error shows everything it printed. It never prints the token.

### Keep the token in its parameter

Leave the registration token in its parameter after the connector registers, expired or not. It is what registers
the role again when the role is replaced, or with `terraform apply -replace`: LoopProof answers `200` to its tenant's
token for the role it already has, whatever the token's expiry, until a new one replaces it. A parameter put back to
`unset`, or holding another value, makes the next of those registrations fail on every apply, until it holds a token
from LoopProof again: before LoopProof has proven your account, a new one from LoopProof's onboarding; after, one an
admin of your tenant mints on LoopProof's Settings page.

A new token is unused, and LoopProof refuses an unused token once its 24 hours have passed, so register with it as
soon as it is in the parameter: `terraform apply -replace=module.<name>.terraform_data.registration`, which LoopProof
answers with `200` and which changes nothing, or a plain `terraform apply` if the registration is tainted. Once it has
registered, it keeps working for the role until a newer one replaces it.

The ARN is only a hint: LoopProof proves the account later by assuming the role.

### A machine that can't reach LoopProof

The registration needs HTTPS from the machine that runs Terraform to `registration_url`. Without it, the apply
creates everything else, then fails at the registration with `curl`'s error, the role's ARN and the Region. Before
LoopProof has proven your account, paste those into LoopProof's onboarding, which registers the role without a
token. The registration stays tainted, so each later apply tries again and fails the same way, until one runs from a
machine that can reach LoopProof.

Once LoopProof has proven your account, it takes no paste: the registration needs a registration token and a machine
that reaches LoopProof. Replacing the role, or `terraform apply -replace` on the registration, from a machine that
can't reach LoopProof, fails at the registration, and so does every later apply from it, until one runs from a
machine that can. LoopProof keeps using the role meanwhile, since a replaced role keeps its ARN. See
[Troubleshooting](https://infrahouse.github.io/terraform-aws-loopproof-connector/troubleshooting/).

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
  parameter and nothing else in SSM: not the ExternalIds' or the token's.
* A change takes effect on the next apply. Make it as you change the rest of your Terraform, by pull request;
  LoopProof doesn't ask why.
* IAM can't limit `securityhub:GetFindings` to some accounts, so the connector role can still read an excluded
  account's findings through `GetFindingsV2`. The list is how LoopProof knows to leave them out.
* EventBridge limits a rule's pattern to 4096 characters, which holds about 250 excluded accounts.

### Resource tags

Where a finding's resource carries no tags, LoopProof takes them from a related resource: an ECR image's from its
repository, which neither Inspector's nor Security Hub's finding carries. The connector role reads them one of two
ways, and needs no input for either:

* **In its own account.** The role may `ecr:ListTagsForResource` on every repository of the account you install it
  in, in every Region, and nothing else of ECR. That's all a single account needs.
* **From AWS Control Tower's Config aggregator,** for an organization with Control Tower, whose findings come from
  other accounts. The role may `config:SelectAggregateResourceConfig` on every Config aggregator of the account you
  install it in, in the module's Region. In the Audit account that includes Control Tower's,
  `aws-controltower-GuardrailsComplianceAggregator`, which LoopProof queries by its name. Control Tower keeps it in
  Control Tower's home Region; if that isn't the Region you apply the module in, the role can't reach it.

  IAM names an aggregator by an ARN that ends in an ID AWS Config generates, not its name, so the grant is
  `config-aggregator/*`: it reaches any other aggregator of that account and Region too, such as one you made
  yourself, and matches nothing where there is none. A query can read whatever an aggregator holds: the
  configuration of every resource it covers, not only their tags, and the excluded accounts' too. IAM can't limit a
  query to some fields or accounts; as with the findings, the excluded accounts' list is how LoopProof knows to leave
  them out.

Where neither read reaches the related resource, LoopProof marks the tags as not derived; it never holds a ticket
back for them.

### Events are refused until LoopProof proves the account

Until LoopProof has proven your account (a later onboarding step, in which it assumes the role), its bus refuses
your events. EventBridge doesn't retry a permission error; without a dead-letter queue, it drops the event and
counts it in the rule's `FailedInvocations` metric. Nothing is lost: once the account is proven, LoopProof imports
your findings' history through the connector role. You don't need to debug those failures.

### Upgrading from 1.0.1

Change the module's version and apply. The plan adds the connector role's policies `ecr-repository-tags` and
`config-aggregator-query`, and changes the role's description, which names them, and its `module_version` tag, in
place; it replaces nothing, and the role doesn't register again. See [Upgrading](https://infrahouse.github.io/terraform-aws-loopproof-connector/upgrading/).

### Upgrading from 0.3.0

This release takes the two parameters' ARNs in place of `external_ids` and `registration_token`, and drops the
`registered` output and the `hashicorp/http` provider. An installed tenant upgrades with the registration token it
installed with. See
[Upgrading](https://infrahouse.github.io/terraform-aws-loopproof-connector/upgrading/).

## Documentation

Full documentation is at [infrahouse.github.io/terraform-aws-loopproof-connector](https://infrahouse.github.io/terraform-aws-loopproof-connector/):

* [Getting Started](https://infrahouse.github.io/terraform-aws-loopproof-connector/getting-started/)
* [Architecture](https://infrahouse.github.io/terraform-aws-loopproof-connector/architecture/)
* [Configuration](https://infrahouse.github.io/terraform-aws-loopproof-connector/configuration/)
* [Security](https://infrahouse.github.io/terraform-aws-loopproof-connector/security/)
* [Troubleshooting](https://infrahouse.github.io/terraform-aws-loopproof-connector/troubleshooting/)
* [Upgrading](https://infrahouse.github.io/terraform-aws-loopproof-connector/upgrading/)

## Requirements

* Terraform `>= 1.10` for the module, and `>= 1.11` for Part 1's write-only placeholder
* AWS provider `>= 6.0`
* `curl` 7.76.0 or later, on Linux or macOS, with HTTPS access to LoopProof's API from the machine that runs
  Terraform
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
| [aws_iam_role_policy.connector_config_aggregator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.connector_excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.connector_repository_tags](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.forwarder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_ssm_parameter.excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [terraform_data.registration](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.connector_config_aggregator](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_excluded_accounts](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_permissions](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.connector_repository_tags](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
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
| <a name="output_region"></a> [region](#output\_region) | Region the module is applied in, where LoopProof reads the Security Hub findings. Before LoopProof has proven<br/>your account, paste it into LoopProof's onboarding with role\_arn if the registration call can't succeed. |
| <a name="output_role_arn"></a> [role\_arn](#output\_role\_arn) | ARN of the connector role. Before LoopProof has proven your account, paste it into LoopProof's onboarding, with<br/>region, if the registration call can't succeed, such as from a machine that can't reach LoopProof. After,<br/>LoopProof takes no paste. |
| <a name="output_role_name"></a> [role\_name](#output\_role\_name) | Name of the connector role, loopproof-<environment>-connector. |
<!-- END_TF_DOCS -->

## Examples

See [examples/](examples/) for a working configuration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
