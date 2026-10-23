# Examples

## The install, in two parts

Part 1 creates the parameters that hold the ExternalIds and the registration token; Part 2 is the module call, with
their ARNs. Both go in one root:

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
  version = "0.3.0"

  environment                      = "production"
  control_plane_account_id         = "123456789012"
  external_ids_parameter_arn       = aws_ssm_parameter.loopproof_external_ids.arn
  registration_token_parameter_arn = aws_ssm_parameter.loopproof_registration_token.arn
  event_bus_arn                    = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url                 = "https://api.loopproof.ai/connector/registrations"
}
```

Apply, fill both parameters, apply again: see [Getting Started](getting-started.md#first-deployment). A runnable
version is in [examples/basic](https://github.com/infrahouse/terraform-aws-loopproof-connector/tree/main/examples/basic).

## Parameters you manage another way

Skip Part 1 and pass the ARNs of your own SecureString parameters, in the account and Region of the AWS provider:

```hcl
module "loopproof_connector" {
  # ...
  external_ids_parameter_arn       = "arn:aws:ssm:us-east-1:111122223333:parameter/security/external-ids"
  registration_token_parameter_arn = "arn:aws:ssm:us-east-1:111122223333:parameter/security/loopproof-token"
}
```

The ExternalIds' parameter must hold a JSON list, such as `["<ExternalId>"]`.

## A customer-managed key

```hcl
resource "aws_ssm_parameter" "loopproof_external_ids" {
  # ...
  key_id = aws_kms_key.loopproof.arn
}
```

Whoever applies the root then needs `kms:Decrypt` on the key, and the fill commands need `--key-id` with it.

## Forward Medium findings too

```hcl
module "loopproof_connector" {
  # ...
  severities = ["Medium", "High", "Critical", "Fatal"]
}
```

## Exclude accounts

Keep the findings of an account outside your audit scope, or of a decommissioned one, in your account:

```hcl
module "loopproof_connector" {
  # ...
  excluded_accounts = ["111122223333"]
}
```

The next apply updates the forwarding rule and the parameter `/loopproof/<environment>/excluded-accounts`, which
LoopProof reads. Set `excluded_accounts = []`, or remove it, to include the account again.

## Rotating the ExternalId

The Terraform doesn't change; the parameter does.

1. Add the new value to the parameter, and apply. LoopProof's calls keep working with the old one. The command
   reads the current list from the parameter and adds the value you type; it prints neither.

    ```bash
    printf 'New ExternalId: ' >&2; stty -echo; read -r new; stty echo; printf '\n' >&2
    current=$(aws ssm get-parameter --with-decryption --name /loopproof/production/external-ids \
      --query Parameter.Value --output text)
    printf '%s' "${current%]},\"$new\"]" | aws ssm put-parameter --overwrite --type SecureString \
      --name /loopproof/production/external-ids --value file:///dev/stdin; unset current new
    terraform apply
    ```

2. Wait at least 10 minutes, then tell LoopProof to switch to the new value.

3. Keep the new value only, and apply. The command keeps the last value of step 1's list, the new one, and prints
   nothing; it expects the two values step 1 left.

    ```bash
    current=$(aws ssm get-parameter --with-decryption --name /loopproof/production/external-ids \
      --query Parameter.Value --output text)
    printf '[%s' "${current##*,}" | aws ssm put-parameter --overwrite --type SecureString \
      --name /loopproof/production/external-ids --value file:///dev/stdin; unset current
    terraform apply
    ```

Neither apply replaces the role: Terraform updates its trust policy in place, and the role doesn't register again.
The wait in step 2 is for IAM: for a few minutes after the first apply, STS still refuses the new value now and then.

## Registering again

`terraform apply -replace=module.loopproof_connector.terraform_data.registration` makes the registration call once
more, with the token in the parameter. LoopProof answers `200` for a role it already has.
