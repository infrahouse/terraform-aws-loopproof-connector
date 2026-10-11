# Getting Started

## Prerequisites

* Security Hub (the OCSF-based Security Hub, which emits "Findings Imported V2" events) enabled.
* Terraform `~> 1.5`, with the AWS provider `~> 6.0`. The module also uses the `hashicorp/http` provider; Terraform
  installs it for you.
* Credentials for the account and Region described below, allowed to manage IAM roles and EventBridge rules.
* The module call from LoopProof's onboarding, the ExternalId, and a registration token (`lprt_…`). The token is
  valid for 24 hours.

## Where to install it

Install the module in the account where Security Hub collects your findings, in Security Hub's home Region:

| Setup | Account |
|-------|---------|
| Control Tower, or an Organization | Security Hub's delegated administrator, usually Audit |
| A single account | That account |

In that account and Region, Security Hub's EventBridge feed carries the findings of every member account and of every
linked Region, and `GetFindingsV2` can read them all.

## First deployment

1. **Store the ExternalId.** Put it in your own parameter store, for example as an SSM `SecureString` parameter:

    ```bash
    aws ssm put-parameter --name /loopproof/external-id --type SecureString --value '<ExternalId>'
    ```

2. **Add the module call** LoopProof generated, reading the ExternalId from the parameter:

    ```hcl
    data "aws_ssm_parameter" "loopproof_external_id" {
      name = "/loopproof/external-id"
    }

    module "loopproof_connector" {
      source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
      version = "0.0.0"

      environment              = "production"
      control_plane_account_id = "123456789012"
      external_ids             = [data.aws_ssm_parameter.loopproof_external_id.value]
      event_bus_arn            = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
      registration_url         = "https://api.loopproof.ai/connector/registrations"
      registration_token       = var.loopproof_registration_token
    }

    variable "loopproof_registration_token" {
      type      = string
      sensitive = true
      default   = null
    }
    ```

3. **Apply with the token**, without writing it to a file:

    ```bash
    TF_VAR_loopproof_registration_token='lprt_…' terraform apply
    ```

    The `registered` output is `true` once LoopProof accepted the role. If the call failed, the error shows the
    role's ARN: paste it into LoopProof's onboarding.

4. **Apply again without the token.** The module stops calling LoopProof, and `registered` becomes `null`.

5. **Finish onboarding in LoopProof.** It proves the account by assuming the role. Until then, LoopProof's bus
   refuses your events; see [Troubleshooting](troubleshooting.md#eventbridge-reports-failed-invocations).
