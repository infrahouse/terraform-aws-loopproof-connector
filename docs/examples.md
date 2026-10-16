# Examples

## ExternalId from SSM Parameter Store

```hcl
data "aws_ssm_parameter" "loopproof_external_id" {
  name = "/loopproof/external-id"
}

module "loopproof_connector" {
  source  = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
  version = "0.2.0"

  environment              = "production"
  control_plane_account_id = "123456789012"
  external_ids             = [data.aws_ssm_parameter.loopproof_external_id.value]
  event_bus_arn            = "arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings"
  registration_url         = "https://api.loopproof.ai/connector/registrations"
}
```

A runnable version is in [examples/basic](https://github.com/infrahouse/terraform-aws-loopproof-connector/tree/main/examples/basic).

## ExternalId from Secrets Manager

```hcl
data "aws_secretsmanager_secret_version" "loopproof_external_id" {
  secret_id = "loopproof/external-id"
}

module "loopproof_connector" {
  # ...
  external_ids = [data.aws_secretsmanager_secret_version.loopproof_external_id.secret_string]
}
```

## Forward Medium findings too

```hcl
module "loopproof_connector" {
  # ...
  severities = ["Medium", "High", "Critical", "Fatal"]
}
```

## Rotating the ExternalId

Store the new value next to the old one, then:

```hcl
# 1. Both values: LoopProof's calls keep working with the old one.
external_ids = [
  data.aws_ssm_parameter.loopproof_external_id_old.value,
  data.aws_ssm_parameter.loopproof_external_id_new.value,
]
```

2. Wait at least 10 minutes, then tell LoopProof to switch to the new value.

```hcl
# 3. The new value only.
external_ids = [data.aws_ssm_parameter.loopproof_external_id_new.value]
```

Neither apply replaces the role: Terraform updates its trust policy in place. The wait in step 2 is for IAM: for a
few minutes after the first apply, STS still refuses the new value now and then.
