# Getting Started

## Prerequisites

* Security Hub (the OCSF-based Security Hub, which emits "Findings Imported V2" events) enabled.
* Terraform `>= 1.11` for the root below (the module itself needs `>= 1.10`), with the AWS provider `>= 6.0`.
* A Linux or macOS machine to run Terraform, with `curl` 7.76.0 or later and HTTPS access to LoopProof's API.
  Windows isn't supported. Without access to the API, see
  [A machine that can't reach LoopProof](#a-machine-that-cant-reach-loopproof).
* The AWS CLI, to fill the parameters.
* Credentials for the account and Region described below, allowed to manage IAM roles, EventBridge rules and SSM
  parameters, and `ssm:GetParameter` on `/loopproof/<environment>/*`; see
  [Security](security.md#permissions-for-whoever-applies-it).
* The two parts of Terraform from LoopProof's onboarding, and the ExternalId and registration token (`lprt_…`) it
  shows you once. The token is valid for 24 hours.

## Where to install it

Install the module in the account where Security Hub collects your findings, in Security Hub's home Region:

| Setup | Account |
|-------|---------|
| Control Tower, or an Organization | Security Hub's delegated administrator, usually Audit |
| A single account | That account |

In that account and Region, Security Hub's EventBridge feed carries the findings of every member account and of every
linked Region, and `GetFindingsV2` can read them all.

With AWS Control Tower, LoopProof also reads the tags of your other accounts' resources from Control Tower's Config
aggregator in Audit, with nothing to set, if Control Tower's home Region is that Region too; see
[Architecture](architecture.md#resource-tags).

## First deployment

1. **Add both parts to one root.** Part 1 creates the two SSM SecureString parameters with the write-only placeholder
   `unset`; Part 2 calls the module with their ARNs:

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

    The placeholder is write-only, so Terraform never stores the value or compares it, and never writes it again.

2. **Apply.** It creates the two parameters, then stops with an error that names the parameter to fill:

    ```text
    Error: Resource postcondition failed

    The SSM parameter
    arn:aws:ssm:us-east-1:111122223333:parameter/loopproof/production/external-ids
    still holds the placeholder "unset".
    Put the ExternalId from LoopProof's onboarding in it, as a JSON list such as
    ["<ExternalId>"], and apply again.
    ```

    Applying with `-target` on the two parameters creates them without the error.

3. **Fill both parameters.** Each command asks for the value without echoing it and passes it to the AWS CLI on its
   standard input, so it is on no command line and in no shell history:

    ```bash
    printf 'ExternalId: ' >&2; stty -echo; read -r value; stty echo; printf '\n' >&2
    printf '["%s"]' "$value" | aws ssm put-parameter --overwrite --type SecureString \
      --name /loopproof/production/external-ids --value file:///dev/stdin; unset value
    ```

    ```bash
    printf 'Registration token: ' >&2; stty -echo; read -r value; stty echo; printf '\n' >&2
    printf '%s' "$value" | aws ssm put-parameter --overwrite --type SecureString \
      --name /loopproof/production/registration-token --value file:///dev/stdin; unset value
    ```

    Use the account and Region of step 2. With a customer-managed KMS key on the parameters, add `--key-id` with it:
    without it, SSM re-encrypts the value with `aws/ssm`.

4. **Apply again.** It creates the connector and registers the role with LoopProof, once. If LoopProof refuses the
   token, the apply fails and says what to do; see
   [Troubleshooting](troubleshooting.md#the-apply-fails-with-loopproof-refused-the-connector-registration).

5. **Finish onboarding in LoopProof.** It proves the account by assuming the role. Until then, LoopProof's bus
   refuses your events; see [Troubleshooting](troubleshooting.md#eventbridge-reports-failed-invocations).

Later plans and applies read the parameters but never call LoopProof. Keep both parameters, since the module reads
them on every plan, and keep the token in its parameter: it registers the role again when the role is replaced. A
lost token has to come from LoopProof: before LoopProof has proven your account, a new one comes from its onboarding;
after, an admin of your tenant mints one on LoopProof's Settings page. Register with a new token within its 24 hours,
since LoopProof refuses an unused token once it has expired:
`terraform apply -replace=module.<name>.terraform_data.registration`, which changes nothing, or a plain apply if the
registration is tainted. See [Security](security.md#the-registration-token).

## A machine that can't reach LoopProof

The registration needs HTTPS from the machine that runs Terraform to `registration_url`. Without it, step 4 creates
everything else, then fails at the registration with `curl`'s error, the role's ARN and the Region. Paste those into
LoopProof's onboarding: before LoopProof has proven your account, that registers the role without a token. The
registration stays tainted, so each later apply tries again and fails the same way, until one runs from a machine
that can reach LoopProof.

Once LoopProof has proven your account, it takes no paste: the registration needs a registration token and a machine
that reaches LoopProof. Replace the role, or run `terraform apply -replace` on the registration, from such a machine.
See
[Troubleshooting](troubleshooting.md#the-registration-fails-on-every-apply-from-a-machine-that-cant-reach-loopproof).
