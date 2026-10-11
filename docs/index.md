# LoopProof connector

The LoopProof connector gives [LoopProof](https://loopproof.ai) the access it needs in your AWS account to turn
your Security Hub findings into Linear tickets, and nothing more:

* **A cross-account IAM role**, `loopproof-<environment>-connector`. LoopProof's control plane assumes it, with an
  ExternalId, to read findings and set their status and comment.
* **Forwarding.** An EventBridge rule sends Security Hub's "Findings Imported V2" events of the severities you
  choose to LoopProof's event bus, through a role that may only put events on that bus.
* **Self-registration.** On the first apply, the module reports the role's ARN to LoopProof with a one-time token.

## Features

* Trust limited to the control plane's `loopproof-<environment>-*` roles and to one or two ExternalIds
* `securityhub:GetFindings` and `securityhub:BatchUpdateFindings` only; updates are confined to status and comment
* Forwarding of new, updated and closed findings by OCSF severity, across accounts and Regions
* ExternalId rotation without a failed `AssumeRole`
* No binary needed on the machine that runs Terraform

## Quick Start

LoopProof's onboarding generates the module call for you. It looks like this:

```hcl
module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "0.1.0"

  environment              = "production"
  control_plane_account_id = "123456789012"
  external_ids             = [var.loopproof_external_id]
  event_bus_arn            = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url         = "https://api.loopproof.ai/connector/registrations"
  registration_token       = var.loopproof_registration_token
}
```

Next: [Getting Started](getting-started.md).
