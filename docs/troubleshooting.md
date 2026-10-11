# Troubleshooting

## EventBridge reports failed invocations

The rule's `FailedInvocations` metric counts events, and LoopProof receives nothing.

**Before LoopProof has proven your account, this is expected.** LoopProof's bus refuses events from accounts it
hasn't verified, which happens in a later onboarding step, when it assumes the connector role. EventBridge doesn't
retry a permission error and, without a dead-letter queue, drops the event
([EventBridge DLQ](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)). Nothing is lost:
once your account is proven, LoopProof imports the history of your findings through the connector role.

If the failures continue after LoopProof shows the account as connected, check that `event_bus_arn` and
`control_plane_account_id` match what onboarding generated, and contact LoopProof.

## The apply fails with "LoopProof did not accept the connector registration"

The registration call got an answer other than `200`. The role and the forwarding were still created.

* Paste the role ARN from the error (or `terraform output role_arn`) into LoopProof's onboarding.
* Remove `registration_token` from the module call and apply again.

A `401` or `403` usually means the token expired (it's valid for 24 hours) or was already used for another role.

## Plans fail days after the installation

If `registration_token` is still set, every plan calls LoopProof again, and fails once LoopProof no longer accepts
the token. Remove `registration_token`; the role stays registered.

## The apply fails with "Error making request"

The registration call didn't get an answer: DNS, a proxy or a firewall. Apply again once
`registration_url` is reachable from the machine that runs Terraform, or paste `role_arn` into LoopProof and remove
the token.

## LoopProof reports AccessDenied when it assumes the role

* The ExternalId in your parameter store isn't the one LoopProof holds. During a rotation, keep both values until
  LoopProof has switched.
* `environment` or `control_plane_account_id` doesn't match LoopProof's environment. The trust policy only accepts
  the roles `loopproof-<environment>-*` of that account.
* IAM applies a trust policy change gradually: for a few minutes after an apply, STS may refuse a newly added
  ExternalId now and then. A value that was already listed keeps working. Wait about 10 minutes before LoopProof
  switches to a new value.

## No Findings Imported V2 events at all

* The module isn't in Security Hub's home Region, or not in the delegated administrator account. Findings of member
  accounts and linked Regions reach EventBridge only there.
* Only Security Hub CSPM is enabled. CSPM emits "Security Hub Findings - Imported" events, which the rule doesn't
  match; LoopProof needs Security Hub.
* `severities` excludes the findings you expect. The default forwards High, Critical and Fatal only.
