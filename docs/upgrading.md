# Upgrading

## From 1.1.0

This release forwards GuardDuty's findings at every severity, whatever `severities` lists. The other products'
findings, such as Inspector's, CSPM's and exposure findings, are forwarded by `severities`, as before, and the
findings of the accounts in `excluded_accounts` stay in your account, GuardDuty's included. See
[Forwarding](architecture.md#forwarding). No input or output changes, and LoopProof's generated module call needs no
change but its version.

### Steps

1. **Change the module's version** and run `terraform init`.
2. **`terraform apply`.** The plan changes the forwarding rule's pattern and description, and the connector role's
   `module_version` tag, in place.

Nothing else changes: the role's trust and policies, the rule's target, the forwarder role and both parameters stay as
they are, and none is replaced. The registration doesn't run again, and the registration token isn't needed. From the
apply on, LoopProof receives GuardDuty's findings below High as Security Hub imports or updates them.

## From 1.0.1

This release lets the connector role read resource tags, for the findings whose resource carries none: the tags of
the account's ECR repositories, and a query of the account's Config aggregators in the module's Region, such as AWS
Control Tower's, which can return any configuration an aggregator holds. See
[Resource tags](architecture.md#resource-tags) and [Security](security.md#permissions). No input or output changes.

### Steps

1. **Change the module's version** and run `terraform init`.
2. **`terraform apply`.** The plan adds the connector role's policies `ecr-repository-tags` and
   `config-aggregator-query`, and changes the role's description, which names them, and its `module_version` tag,
   in place.

Nothing else changes: the role's trust and its other policies, the forwarding rule and both parameters stay as they
are, and none is replaced. The registration doesn't run again, and the registration token isn't needed.

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

1. **Check the machine that runs Terraform:** Linux or macOS, `curl` 7.76.0 or later, HTTPS access to
   `registration_url`, and Terraform 1.11 or later.
2. **Find the registration token you installed with.** The upgrade registers the role once more, with the token in
   the parameter, and LoopProof answers `200` to its tenant's token for the role it already has, whatever the token's
   expiry, unless a newer one has replaced it. Without a token that works, the upgrade's apply fails at the
   registration, and so does every apply after it, the registration staying tainted. If you no longer have it, get a
   new one, and upgrade within 24 hours of getting it: the upgrade's apply registers with it, and LoopProof refuses an
   unused token once it has expired. Once LoopProof has proven your account, an admin of your tenant mints one on
   LoopProof's Settings page; before, it comes from LoopProof's onboarding.
3. **Add Part 1** to the root, the two parameters, as in [Getting Started](getting-started.md#first-deployment).
4. **Change the module call:** set `version` to this release, remove `external_ids` and `registration_token`, and add
   `external_ids_parameter_arn` and `registration_token_parameter_arn` with the two parameters' ARNs. Remove the
   variables or data sources that fed the old inputs, and any use of the `registered` output.
5. **Create the parameters:** `terraform apply -target` on the two parameters.
6. **Fill them:** the ExternalIds' parameter with the value or values you passed in `external_ids`, as a JSON list,
   and the token's parameter with the registration token you installed with.
7. **`terraform apply`.** The plan shows the connector role's trust policy unchanged, since the ExternalIds are the
   same, and adds `terraform_data.registration`, which registers the role once.

Keep the token in its parameter afterwards: it registers the role again if the role is ever replaced. The next
`terraform init` drops the `hashicorp/http` provider from the lock file if nothing else in the root uses it.
