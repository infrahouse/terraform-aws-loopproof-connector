# Configuration

LoopProof's onboarding fills in every input. The ExternalIds and the registration token aren't inputs: the module
reads them from two SSM parameters, whose ARNs are.

## Inputs

### `environment`

LoopProof's environment, such as `staging` or `production`: 1 to 44 lowercase letters, digits or hyphens. It names
the resources (`loopproof-<environment>-connector`, `-forwarder`, `-findings`) and selects the control-plane roles
that may assume the connector role (`loopproof-<environment>-*`).

### `control_plane_account_id`

LoopProof's control-plane account for that environment. Twelve digits.

### `external_ids_parameter_arn`

The ARN of the SSM SecureString parameter that holds the ExternalIds LoopProof presents when it assumes the role, as a
JSON list: one value, or two during a [rotation](security.md#rotating-the-externalid), such as `["<ExternalId>"]`.
Pass `aws_ssm_parameter.<name>.arn` from Part 1, or the ARN of a parameter you manage another way.

The module reads it with a data source, decrypted, on every plan and apply. Before using the value, it checks it, and
fails the run with a message that names the parameter and never shows the value:

* the placeholder `unset`: "still holds the placeholder";
* anything but a JSON list of one or two ExternalIds, each 43 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`, none
  twice.

The validation message for a value that isn't an SSM parameter ARN doesn't repeat it; Terraform shows the value it
was given beside the message, as for any input that isn't sensitive.

### `registration_token_parameter_arn`

The ARN of the SSM SecureString parameter that holds the registration token (`lprt_…`) from LoopProof's onboarding.
The module reads it as an ephemeral value, so the token is in neither the plan nor the state, and uses it for the one
[registration](#registration). The registration fails, naming the parameter, if it holds the placeholder `unset` or
something that doesn't look like a token. Validated as an SSM parameter ARN like `external_ids_parameter_arn`.

### `event_bus_arn`

LoopProof's EventBridge bus, which receives the forwarded findings. It must be an event bus ARN in the
control-plane account.

### `registration_url`

LoopProof's registration endpoint, such as `https://api.staging.loopproof.ai/connector/registrations`. The module
POSTs the role's ARN and the Region it's applied in there; see [Registration](#registration). It must use
`https://`, without credentials in the URL; `http://` is accepted only for `127.0.0.1` and `localhost`, which the
module's tests use.

### `severities`

Default `["High", "Critical", "Fatal"]`. The severities to forward, as Security Hub writes them in the OCSF `severity`
field: `Unknown`, `Informational`, `Low`, `Medium`, `High`, `Critical`, `Fatal`, `Other`. Values are case-sensitive;
the ASFF labels of Security Hub CSPM, such as `HIGH`, are rejected.

```hcl
severities = ["Medium", "High", "Critical", "Fatal"]
```

### `excluded_accounts`

Default `[]`. The AWS accounts you keep out of LoopProof, such as an account outside your audit scope or a
decommissioned one: twelve digits each, each listed once. Validation messages name the input but don't echo the
values.

```hcl
excluded_accounts = ["111122223333", "444455556666"]
```

* The forwarding rule drops their findings, by the finding's account, `cloud.account.uid`: they never leave your
  account.
* The module publishes the list, sorted, as JSON in the `String` parameter `/loopproof/<environment>/excluded-accounts`
  in the module's Region, such as `["111122223333","444455556666"]`, or `[]` when you exclude nothing. LoopProof reads
  it with the connector role when it proves your account and daily after. The plan shows the list.
* A change takes effect on the next apply, which updates the rule and the parameter in place. The order doesn't
  matter: the module sorts the list.
* EventBridge limits a rule's pattern to 4096 characters, which holds about 250 accounts.

## Outputs

| Output | Description |
|--------|-------------|
| `role_arn` | ARN of the connector role. Paste it into LoopProof, with `region`, if the registration call failed. |
| `region` | The module's Region, where LoopProof reads the findings. Paste it with `role_arn` if registration failed. |
| `role_name` | `loopproof-<environment>-connector` |
| `event_rule_arn` | ARN of the EventBridge rule |
| `excluded_accounts_parameter` | `/loopproof/<environment>/excluded-accounts`, which publishes `excluded_accounts` |

No output contains an ExternalId or the token. 0.3.0's `registered` output is gone: an apply that finishes has
registered the role, since a refused registration fails it.

## Registration

The module reports the role's ARN and the AWS provider's Region to `registration_url`, once: when its
`terraform_data.registration` resource is created, on the apply that creates the role. A `local-exec` provisioner
runs `files/register.sh` with `/bin/sh`, which POSTs `{"role_arn": "...", "region": "..."}` with `curl`. LoopProof
reads your Security Hub findings in that Region; an IAM role ARN names no Region, so the call carries it.

* The token reaches the script through the provisioner's environment, from the ephemeral read, and `curl` through
  its standard input; it is on no command line, in the plan or in the state.
* `curl -sS --fail-with-body --max-time 30`. The script checks `command -v curl` first, and `curl --version` for
  7.76.0 or later, which added `--fail-with-body`, and fails with a plain message if either is wrong.
* A 2xx answer registers. A 4xx fails at once; connection errors, timeouts and 5xx answers are tried again, four
  attempts in all, two, four and eight seconds apart.
* Later plans and applies make no call. The call runs again when the role is replaced, and with
  `terraform apply -replace=module.<name>.terraform_data.registration`.
* A failed call fails the apply and leaves the resource tainted, so the next plain apply calls again.

While the script runs, Terraform shows its output as `(output suppressed due to ephemeral value in config)`, because
its environment holds the token. When it fails, the error shows all it printed, and never the request or the token:

```text
Error: local-exec provisioner error

Error running command '.terraform/modules/loopproof_connector/files/register.sh':
exit status 1. Output: LoopProof refused the connector registration: HTTP/2 401
LoopProof's answer: {"detail": "..."}
Get a new registration token in LoopProof and put it in the SSM parameter
arn:aws:ssm:us-east-1:111122223333:parameter/loopproof/production/registration-token, then apply again.
Or paste the connector role ARN and the Region into LoopProof's onboarding:
Role ARN: arn:aws:iam::111122223333:role/loopproof-production-connector
Region: us-east-1
```

## Tags

Every resource gets `created_by_module = "infrahouse/loopproof-connector/aws"` and
`loopproof_environment = <environment>`; the connector role also gets `module_version`. Add your own with the AWS
provider's `default_tags`.
