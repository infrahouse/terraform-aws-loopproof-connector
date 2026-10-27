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

## The apply fails with "still holds the placeholder"

A parameter still holds `unset`, what Part 1 creates it with. Fill it, then apply again:

* the ExternalIds' parameter fails at plan or apply, before the connector role exists. Put the ExternalId in it, as a
  JSON list such as `["<ExternalId>"]`;
* the token's parameter fails at the registration, after the role is created. Put the registration token in it.

See [Getting Started](getting-started.md#first-deployment) for the commands. On the first apply of a new root, the
ExternalIds' error is expected: the parameters didn't exist until that apply.

## The apply fails with "must hold a JSON list of one ExternalId"

The ExternalIds' parameter holds something else: not JSON, a JSON string instead of a list, an empty list, three
values, the same value twice, or a value that isn't 43 characters of `A-Z`, `a-z`, `0-9`, `_` or `-`. The message
doesn't show the value; read it with `aws ssm get-parameter --with-decryption` and put it back as `["<ExternalId>"]`,
or `["<old>","<new>"]` during a rotation.

## The apply fails with "LoopProof refused the connector registration"

LoopProof answered the registration with a 4xx. The role and the forwarding were created; only the registration
failed, and it is tainted.

* A `401` usually means the token expired before it registered anything (it's valid for 24 hours), or was replaced
  by a newer one. A `409` means the token already registered another role or, once LoopProof has proven your account,
  that this role isn't the one your tenant has; LoopProof's answer says which.
* Get a new registration token, put it in the token parameter, and run a plain `terraform apply`: the tainted
  registration runs again by itself. Where the token comes from depends on whether LoopProof has proven your account:
  * before, from LoopProof's onboarding;
  * after, an admin of your tenant mints one on LoopProof's Settings page, with "Mint a new registration token". A
    minted token registers only the role your tenant already has, so it can't fix a `409`: nothing changes the role
    LoopProof has for your tenant.

  A new token replaces the one before it, which stops working at once.
* The token the connector registered with also works again, if you still have it and no newer one has replaced it:
  LoopProof keeps accepting its tenant's token for the role it already has.
* Before LoopProof has proven your account, you can instead paste the role ARN and the Region from the error, or the
  `role_arn` and `region` outputs, into LoopProof's onboarding. Once it has, LoopProof takes no paste.

## The apply fails with "didn't answer" or a 5xx

The registration got no answer (DNS, a proxy, a firewall, a timeout) or LoopProof answered 5xx, four times. Apply
again once `registration_url` is reachable from the machine that runs Terraform. Before LoopProof has proven your
account, you can instead paste the role ARN and the Region into LoopProof's onboarding. Once it has, LoopProof takes
no paste: the registration needs a registration token and a machine that reaches LoopProof. From a machine that can
never reach LoopProof, each apply fails the same way; see
[the next section](#the-registration-fails-on-every-apply-from-a-machine-that-cant-reach-loopproof).

## The registration fails on every apply, from a machine that can't reach LoopProof

The registration runs on the apply that creates the role, when the role is replaced, and with
`terraform apply -replace` on `module.<name>.terraform_data.registration`. From a machine without HTTPS access to
`registration_url`, it fails, stays tainted, and fails again on every later apply from that machine.

* **Before LoopProof has proven your account,** paste the role ARN and the Region into LoopProof's onboarding, which
  registers the role without a token, as in
  [A machine that can't reach LoopProof](getting-started.md#a-machine-that-cant-reach-loopproof). The registration
  stays tainted until an apply runs from a machine that reaches LoopProof.
* **Once LoopProof has proven your account,** there is no way to register from that machine: LoopProof takes no
  paste, and a registration token works only in a call that reaches LoopProof. Run one apply from a machine that
  reaches LoopProof, with a registration token in the parameter: the one the connector registered with, if no newer
  one has replaced it, or a new one an admin of your tenant mints on LoopProof's Settings page. Until then, LoopProof
  keeps using the role, since a replaced role keeps its ARN, but every apply from the other machine fails at the
  registration.

## The apply fails with "registers the connector role with curl, which isn't on PATH"

Install `curl` 7.76.0 or later on the machine that runs Terraform, and apply again. Windows isn't supported.

## The apply fails with "registers the connector role with curl 7.76.0 or later"

The machine's `curl` is older than 7.76.0, which added `--fail-with-body`; RHEL and Rocky Linux 8 ship 7.61, and
Debian 11 ships 7.74. Install a newer `curl` first on `PATH`, or apply from another machine, and apply again.

## The plan fails with ParameterNotFound or AccessDeniedException

The module reads both parameters on every plan. Check that they still exist, in the account and Region of the AWS
provider, and that your credentials allow `ssm:GetParameter` on them, and `kms:Decrypt` with a customer-managed key;
see [Security](security.md#permissions-for-whoever-applies-it).

## LoopProof can't derive the tags of another account's resources

LoopProof reads them from AWS Control Tower's Config aggregator, `aws-controltower-GuardrailsComplianceAggregator`,
by its name, in the account and Region the module is applied in. It marks the tags as not derived, and never holds a
ticket back, when:

* the organization has no Control Tower, so there's no such aggregator;
* Control Tower's home Region isn't the module's Region, Security Hub's home Region: the role may query aggregators
  in the module's Region only;
* the connector is older than the release that added `config-aggregator-query`.

The tags of the module's own account's ECR repositories don't depend on any of these.

## LoopProof reports AccessDenied when it assumes the role

* The ExternalIds' parameter doesn't hold the value LoopProof holds. During a rotation, keep both values until
  LoopProof has switched, and apply after each change: the trust policy changes only on apply.
* `environment` or `control_plane_account_id` doesn't match LoopProof's environment. The trust policy only accepts
  the roles `loopproof-<environment>-*` of that account.
* IAM applies a trust policy change gradually: for a few minutes after an apply, STS may refuse a newly added
  ExternalId now and then. A value that was already listed keeps working. Wait about 10 minutes before LoopProof
  switches to a new value.

## One account's findings never reach LoopProof

* `excluded_accounts` lists the account. Its findings stay in your account by design; the parameter
  `/loopproof/<environment>/excluded-accounts` shows the list the last apply published.
* The account isn't a member of the Security Hub you installed the module in.

## No Findings Imported V2 events at all

* The module isn't in Security Hub's home Region, or not in the delegated administrator account. Findings of member
  accounts and linked Regions reach EventBridge only there.
* Only Security Hub CSPM is enabled. CSPM emits "Security Hub Findings - Imported" events, which the rule doesn't
  match; LoopProof needs Security Hub.
* `severities` excludes the findings you expect. The default forwards High, Critical and Fatal only.
