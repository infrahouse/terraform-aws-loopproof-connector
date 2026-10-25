# Security

## Trust

The connector role trusts only the control-plane account, and within it only roles named
`loopproof-<environment>-*` (`aws:PrincipalArn`), presenting one of the configured ExternalIds (`sts:ExternalId`).
A role of another environment, another account, or any caller without the ExternalId is refused.

## Permissions

The role can read findings, set their status and comment, and read the list of the accounts you exclude, and nothing
else:

* `securityhub:GetFindings`, which `GetFindingsV2` requires;
* `securityhub:BatchUpdateFindings`, which `BatchUpdateFindingsV2` requires, denied when the request sets
  `SeverityId` or sets neither `StatusId` nor `Comment`;
* `ssm:GetParameter` on `/loopproof/<environment>/excluded-accounts` alone. That's a `String` parameter, which KMS
  doesn't encrypt, so the role has no KMS permission. It can't read the parameters that hold the ExternalIds and the
  token.

There is no `iam:*`, no wildcard action, and no access to data outside Security Hub but that parameter. The two
Security Hub actions take `"Resource": "*"`: their resource types are optional, and AWS doesn't document which ARN the
V2 APIs are authorized against. `securityhub:GetFindings` also authorizes the ASFF `GetFindings` API of Security Hub
CSPM; IAM can't tell the two apart.

The forwarder role may only `events:PutEvents` on LoopProof's bus, and only EventBridge, for this rule, may assume it.

## Permissions for whoever applies it

Besides what managing IAM roles, EventBridge rules and SSM parameters takes:

* `ssm:GetParameter` on `/loopproof/<environment>/*`. The module reads both parameters, decrypted, on every plan and
  apply, and Terraform refreshes Part 1's parameters.
* `kms:Decrypt` on the key, if Part 1 gives the parameters a customer-managed key (`key_id`). With the default
  `aws/ssm`, whose key policy allows the account's principals to use it through SSM, nothing more is needed.

Filling the parameters takes `ssm:PutParameter`, and with a customer-managed key `kms:Encrypt` and
`kms:GenerateDataKey` too.

## Excluded accounts

The findings of the accounts in `excluded_accounts` never leave your account: the forwarding rule drops them. IAM
can't limit `securityhub:GetFindings` to some accounts, so the connector role can still read their findings through
`GetFindingsV2`; LoopProof reads the list from the parameter to leave them out. The list itself isn't secret: the plan
shows it, and anyone in your account allowed `ssm:GetParameter` on it can read it.

## The ExternalId

LoopProof generates the ExternalId and treats it as a credential, and so does the module:

* it isn't an input: the module reads it from the SSM SecureString parameter whose ARN you pass, so it is never in
  your code or a tfvars file;
* Part 1 creates the parameter with a write-only placeholder, so Terraform keeps no copy of what you put in it;
* the module checks the value before it uses it, and its messages name the parameter, never the value;
* the plan shows the connector role's trust policy as `(sensitive value)`: Terraform doesn't carry the parameter
  value's sensitivity into the JSON of a policy document, so the module marks it;
* no output, tag or description contains it.

These places hold it anyway, by design:

* the role's trust policy, readable by anyone in your account allowed `iam:GetRole`;
* the Terraform state: the module's read of the parameter and the trust policy. Protect the state as you protect
  other credentials;
* every saved plan file (`terraform plan -out`), which holds the same as the state. Pipelines often keep plan files
  as artifacts, protected less than the state: protect them as you protect the state.

## Rotating the ExternalId

1. Put both values in the parameter, `["<old>","<new>"]`, and apply. The old one keeps working throughout.
2. Wait at least 10 minutes, then tell LoopProof to switch; it presents the new one from then on.
3. Put the new one only, `["<new>"]`, and apply.

Your Terraform doesn't change. Each apply updates the trust policy in place; the role isn't replaced, so it doesn't
register again. IAM applies the change gradually: in the module's tests, STS refused a newly added ExternalId now
and then for up to about four minutes after the apply, while the value listed before and after the change was never
refused. Hence the wait in step 2, and the old value stays listed until LoopProof has switched. The tests also hold
each step until the change has been in effect for five minutes without a refusal.

The same lag applies the other way: after step 3, STS still accepts the removed value now and then for a few
minutes. If an ExternalId leaked, count on it being revoked only once that has passed, and remember that it is only
half of the access: the caller must also be one of LoopProof's control-plane roles.

## The registration token

The token (`lprt_…`) is valid for 24 hours and only lets LoopProof learn your role's ARN and the Region you applied
the module in. The ARN is just a hint: LoopProof proves the account by assuming the role. The module:

* reads it with `ephemeral "aws_ssm_parameter"`, so it is in neither the plan nor the state;
* hands it to the registration script through the provisioner's environment, never its command, and the script
  hands it to `curl` on standard input, so it is on no command line, where another user of the machine could read
  it in the process list;
* never prints it: the script runs without `set -x` or `curl -v`, and prints only the answer's status, LoopProof's
  message and what to do;
* refuses any URL but `https://` (or a loopback address), and URLs with credentials in them.

Keep the token in its parameter after the connector registers, expired or not. The registration runs again when the
role is replaced, or with `terraform apply -replace`, with the token in the parameter, and LoopProof answers `200` to
its tenant's token for the role it already has, whatever the token's expiry. A parameter put back to `unset`, or
holding another value, makes such a registration fail on every apply, until it holds a token from LoopProof again.
Once spent, the token gives nothing but that repeat: LoopProof refuses it for any other role.

A lost token is replaced in LoopProof, and where depends on whether LoopProof has proven your account:

* before, LoopProof's onboarding gives a new one, and also takes the role's ARN and the Region pasted in instead;
* after, an admin of your tenant mints one on LoopProof's Settings page, and LoopProof takes no paste. A minted token
  registers only the role your tenant already has, and changes nothing at LoopProof. Only the tenant's admins can
  mint one, and LoopProof records each mint in the tenant's audit trail.

A new token, from either place, replaces the one before it, which stops working at once, the one in your parameter
included. The module can't tell which case applies, so its error messages name both.

A new token is unused, and LoopProof refuses an unused token once its 24 hours have passed. Register with it as soon
as it is in the parameter: `terraform apply -replace=module.<name>.terraform_data.registration`, which LoopProof
answers with `200` and which changes nothing, or a plain `terraform apply` if the registration is tainted. Once it has
registered, it keeps working for the role until a newer one replaces it.

## Debug logs

At `TF_LOG=DEBUG` the AWS provider logs the responses of its AWS calls, but an ephemeral resource's. A debug log of a
root that holds both parts therefore holds both values: Terraform's refresh of Part 1's parameters reads them
decrypted, and the module's read of the ExternalIds and the role's trust policy show the ExternalIds. The module's
read of the token shows nothing. Treat a debug log of this root as a secret, and turn debug logging off when you're
done with it.

## Uninstalling

`terraform destroy` deletes the connector, and Part 1's parameters with their values. That is right for an
uninstall; know it before you destroy the root for another reason.
