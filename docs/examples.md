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
  version = "1.4.0"

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

This adds Inspector's, CSPM's and exposure findings of Medium severity. GuardDuty's are forwarded at every severity
already, whatever `severities` lists.

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

## Accept a risk

Accept port probes on your VPN endpoints, which are public by design, once its register entry, `SEC-42`, is in your
Linear's "LoopProof risk register" project:

```hcl
module "loopproof_connector" {
  # ...
  threat_accept_rules = [
    {
      id            = "vpn-port-probes"
      finding_types = ["Recon:EC2/PortProbeUnprotectedPort"]
      where = {
        tags     = { role = "vpn" }
        accounts = ["111122223333"]
      }
      reason       = "VPN endpoints are public by design"
      review_by    = "2027-03-31"
      decision_ref = "SEC-42"
    },
  ]
}
```

A vulnerability you accept, in `vulnerability_accept_rules`, names its CVEs, a package and its version, or both, and
where it applies. Here, a package and its version, which accepts every CVE in that version:

```hcl
  vulnerability_accept_rules = [
    {
      id           = "legacy-glibc"
      package      = { name = "glibc", version = "2.26-64.amzn2.0.1" }
      where        = { resource_ids = ["i-0123456789abcdef0"] }
      reason       = "The instance is retired in January"
      review_by    = "2027-01-31"
      decision_ref = "OPS-7"
    },
  ]
```

The next apply publishes each rule in `/loopproof/<environment>/accept-rules/<id>`, and LoopProof reads them within 15
minutes, or at once from its Settings page. To renew a rule, change its `review_by`; to stop it, remove it.

## Accept a CVE in one package

A CVE can be reported against several packages on one host. Terrapin, `CVE-2023-48795`, is reported against openssh
and libssh. On a host whose sshd is off and whose SSH service is libssh's, accept it in openssh and keep libssh's as
work, with a rule that names both the CVE and the package:

```hcl
  vulnerability_accept_rules = [
    {
      id           = "terrapin-openssh"
      cves         = ["CVE-2023-48795"]
      package      = { name = "openssh" } # at any version
      where        = { resource_ids = ["i-0123456789abcdef0"] }
      reason       = "sshd is off on this host; its SSH service is libssh's"
      review_by    = "2027-02-28"
      decision_ref = "SEC-45"
    },
  ]
```

* The rule accepts a finding only when both hold: its CVE is among `cves`, and it is in openssh.
* `openssh` is the source package, the one LoopProof files the work under. A binary package's name, such as
  `openssh-server`, matches nothing.
* Beside `cves` the version is optional. Without one, the rule keeps accepting the CVE in openssh after an update that
  doesn't fix it. With one, such as `version = "8.7p1-38.amzn2023.0.4"` (`version-release`, no epoch), it accepts that
  version only, and after such an update the finding is work again. A misspelled `version`, such as `versoin`, isn't
  refused here: Terraform drops it, and the rule accepts the CVE at every version, so check the published `package` in
  the plan.
* A rule with `cves` alone would accept the CVE in libssh too, since `where` narrows by resource, not by package; a
  rule with the package alone would accept every other CVE in that version of openssh.

## Your policy's SLA targets

Your security policy gives a Critical vulnerability 15 days and a High one 30, and LoopProof's defaults are 7 and 14.
Set the targets in `tenant_settings`, with Medium's and Low's, which must be no shorter than High's:

```hcl
module "loopproof_connector" {
  # ...
  tenant_settings = {
    sla_target_days = {
      vuln_remediation = { critical = 15, high = 30, medium = 60, low = 180 }
    }
  }
}
```

The plan shows the parameter `/loopproof/<environment>/tenant-settings` changing, with every setting: the threats'
targets, the thresholds and the rest keep LoopProof's defaults. LoopProof reads it within 15 minutes of the apply and
records the change in your tenant's audit trail. Work items that open after that are due by the new targets; open ones
keep their due dates. If a grace window is no longer shorter than its new target, LoopProof turns your grace policy
off, and you set one that fits on its Settings page. See [Configuration](configuration.md#tenant_settings).

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
