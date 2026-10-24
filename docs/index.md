# LoopProof connector

The LoopProof connector gives [LoopProof](https://loopproof.ai) the access it needs in your AWS account to turn
your Security Hub findings into Linear tickets, and nothing more:

* **A cross-account IAM role**, `loopproof-<environment>-connector`. LoopProof's control plane assumes it, with an
  ExternalId, to read findings and set their status and comment.
* **Forwarding.** An EventBridge rule sends Security Hub's "Findings Imported V2" events of the severities you
  choose to LoopProof's event bus, through a role that may only put events on that bus.
* **Excluded accounts.** The findings of the accounts you exclude never leave your account, and an SSM parameter
  tells LoopProof which they are.
* **Self-registration.** On the apply that creates the role, the module reports the role's ARN and the Region to
  LoopProof, once, with a registration token.
* **Credentials in your parameter store.** The ExternalIds and the token live in SSM SecureString parameters in your
  account; the module reads them, so neither is ever in your code, and the token is in neither the plan nor the
  state.

## Features

* Trust limited to the control plane's `loopproof-<environment>-*` roles and to one or two ExternalIds
* `securityhub:GetFindings` and `securityhub:BatchUpdateFindings` only; updates are confined to status and comment
* Forwarding of new, updated and closed findings by OCSF severity, across accounts and Regions
* Account exclusion at the edge, with the list published for LoopProof in SSM
* ExternalId rotation without a failed `AssumeRole`, and without a change to your Terraform
* One registration call, at apply, with `curl`; no call on a plan

## Quick Start

LoopProof's onboarding generates the Terraform for you, in two parts that go in one root. Part 1 creates two SSM
SecureString parameters with a write-only placeholder; Part 2 passes their ARNs to the module:

```hcl
resource "aws_ssm_parameter" "loopproof_external_ids" {
  name             = "/loopproof/production/external-ids"
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

resource "aws_ssm_parameter" "loopproof_registration_token" {
  name             = "/loopproof/production/registration-token"
  type             = "SecureString"
  value_wo         = "unset"
  value_wo_version = 1
}

module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "1.0.0"

  environment                      = "production"
  control_plane_account_id         = "123456789012"
  external_ids_parameter_arn       = aws_ssm_parameter.loopproof_external_ids.arn
  registration_token_parameter_arn = aws_ssm_parameter.loopproof_registration_token.arn
  event_bus_arn                    = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url                 = "https://api.loopproof.ai/connector/registrations"
}
```

Then apply, fill both parameters, and apply again. Next: [Getting Started](getting-started.md).
