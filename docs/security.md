# Security

## Trust

The connector role trusts only the control-plane account, and within it only roles named
`loopproof-<environment>-*` (`aws:PrincipalArn`), presenting one of the configured ExternalIds (`sts:ExternalId`).
A role of another environment, another account, or any caller without the ExternalId is refused.

## Permissions

The role can read findings and set their status and comment, and nothing else:

* `securityhub:GetFindings`, which `GetFindingsV2` requires;
* `securityhub:BatchUpdateFindings`, which `BatchUpdateFindingsV2` requires, denied when the request sets
  `SeverityId` or sets neither `StatusId` nor `Comment`.

There is no `iam:*`, no wildcard action, and no access to data outside Security Hub. Both actions take
`"Resource": "*"`: their resource types are optional, and AWS doesn't document which ARN the V2 APIs are authorized
against. `securityhub:GetFindings` also authorizes the ASFF `GetFindings` API of Security Hub CSPM; IAM can't tell the
two apart.

The forwarder role may only `events:PutEvents` on LoopProof's bus, and only EventBridge, for this rule, may assume it.

## The ExternalId

LoopProof generates the ExternalId and treats it as a credential, and so does the module:

* `external_ids` is a sensitive variable, and validation messages don't echo it;
* the plan shows the connector role's trust policy as `(sensitive value)`: Terraform doesn't carry a variable's
  sensitivity into the JSON of a policy document, so the module marks it;
* no output, tag or description contains it.

Keep it in your own parameter store and pass it in; never commit it. Two places hold it anyway, by design:

* the role's trust policy, readable by anyone in your account allowed `iam:GetRole`;
* the Terraform state, like every input. Protect the state as you protect other credentials.

## Rotating the ExternalId

1. Apply with both values, `[old, new]`. The old one keeps working throughout.
2. Wait at least 10 minutes, then tell LoopProof to switch; it presents the new one from then on.
3. Apply with the new one only, `[new]`.

Each apply updates the trust policy in place; the role isn't replaced. IAM applies the change gradually: in the
module's tests, STS refused a newly added ExternalId now and then for up to about four minutes after the apply, while
the value listed before and after the change was never refused. Hence the wait in step 2, and the old value stays
listed until LoopProof has switched. The tests also hold each step until the change has been in effect for five
minutes without a refusal.

The same lag applies the other way: after step 3, STS still accepts the removed value now and then for a few
minutes. If an ExternalId leaked, count on it being revoked only once that has passed, and remember that it is only
half of the access: the caller must also be one of LoopProof's control-plane roles.

## The registration token

The token (`lprt_…`) is valid for 24 hours and only lets LoopProof learn your role's ARN, which is just a hint:
LoopProof proves the account by assuming the role. The module:

* marks `registration_token` sensitive; the plan shows the `Authorization` header as `(sensitive value)`, and the
  apply prints only the URL;
* never writes it to an output;
* refuses any URL but `https://` (or a loopback address), and URLs with credentials in them.

While the token is set, the Terraform state holds it, in the request headers of the data source. Removing the token
after the first apply also removes it from the state.
