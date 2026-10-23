# Upgrading

## From 0.3.0

This release reads the ExternalIds and the registration token from two SSM parameters in your account, and registers
once, at apply, with `curl`. Its interface changed:

* `external_ids`, a sensitive list, becomes `external_ids_parameter_arn`: the ARN of a SecureString parameter that
  holds the list as JSON.
* `registration_token`, sensitive and set for the first apply, becomes `registration_token_parameter_arn`: the ARN of
  a SecureString parameter that holds the token.
* The `registered` output is gone: an apply that finishes has registered the role.
* The `hashicorp/http` provider, which called LoopProof on every plan while the token was set, gives way to `curl` on
  the machine that runs Terraform, which calls once, when the registration resource is created.
* Terraform `~> 1.5` becomes `>= 1.10`, and `>= 1.11` for Part 1's write-only placeholder; the AWS provider `~> 6.0`
  becomes `>= 6.0`.

Nothing else changes: the role, its trust and permissions, the forwarding rule and the excluded accounts' parameter
stay as they are, and none is replaced.

### Steps

1. **Check the machine that runs Terraform:** Linux or macOS, `curl`, HTTPS access to `registration_url`, and
   Terraform 1.11 or later.
2. **Add Part 1** to the root, the two parameters, as in [Getting Started](getting-started.md#first-deployment).
3. **Change the module call:** set `version` to this release, remove `external_ids` and `registration_token`, and add
   `external_ids_parameter_arn` and `registration_token_parameter_arn` with the two parameters' ARNs. Remove the
   variables or data sources that fed the old inputs, and any use of the `registered` output.
4. **Create the parameters:** `terraform apply -target` on the two parameters.
5. **Fill them:** the ExternalIds' parameter with the value or values you passed in `external_ids`, as a JSON list,
   and the token's parameter with the registration token you installed with. LoopProof answers `200` to a token of
   the tenant that already has this role, even an expired one. Without it, get a new token in LoopProof.
6. **`terraform apply`.** The plan shows the connector role's trust policy unchanged, since the ExternalIds are the
   same, and adds `terraform_data.registration`, which registers the role once.

The next `terraform init` drops the `hashicorp/http` provider from the lock file if nothing else in the root uses it.
