# Configuration

LoopProof's onboarding fills in every input except the credentials, which you feed in from your own store.

## Inputs

### `environment`

LoopProof's environment, such as `staging` or `production`: 1 to 44 lowercase letters, digits or hyphens. It names
the resources (`loopproof-<environment>-connector`, `-forwarder`, `-findings`) and selects the control-plane roles
that may assume the connector role (`loopproof-<environment>-*`).

### `control_plane_account_id`

LoopProof's control-plane account for that environment. Twelve digits.

### `external_ids`

**Sensitive.** The ExternalIds LoopProof presents when it assumes the role: one value, or two during a
[rotation](security.md#rotating-the-externalid). Each is 43 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`. Validation
messages never echo the values.

### `event_bus_arn`

LoopProof's EventBridge bus, which receives the forwarded findings. It must be an event bus ARN in the
control-plane account.

### `registration_url`

LoopProof's registration endpoint, such as `https://api.staging.loopproof.ai/connector/registrations`. It must use
`https://`, without credentials in the URL; `http://` is accepted only for `127.0.0.1` and `localhost`, which the
module's tests use.

### `registration_token`

**Sensitive**, default `null`. The one-time token (`lprt_…`) from LoopProof's onboarding, valid for 24 hours. Set it
for the first apply, then remove it. With `null`, the module makes no call. See [Registration](#registration).

### `severities`

Default `["High", "Critical", "Fatal"]`. The severities to forward, as Security Hub writes them in the OCSF `severity`
field: `Unknown`, `Informational`, `Low`, `Medium`, `High`, `Critical`, `Fatal`, `Other`. Values are case-sensitive;
the ASFF labels of Security Hub CSPM, such as `HIGH`, are rejected.

```hcl
severities = ["Medium", "High", "Critical", "Fatal"]
```

## Outputs

| Output | Description |
|--------|-------------|
| `role_arn` | ARN of the connector role. Paste it into LoopProof if the registration call failed. |
| `role_name` | `loopproof-<environment>-connector` |
| `event_rule_arn` | ARN of the EventBridge rule |
| `registered` | `true` once LoopProof accepted the registration, `null` without a token |

No output contains an ExternalId or the token.

## Registration

The module reports the role's ARN with the `hashicorp/http` data source, so the machine running Terraform needs no
`curl` or other binary. Data sources are read on every plan, so while `registration_token` is set:

* every `plan`, `apply` and `destroy` POSTs the same request again. LoopProof answers `200` to a repeat of the same
  token with the same ARN, so that's harmless;
* if LoopProof stops accepting the token, for example after it expires, the plan fails. Remove the token.

On the first apply, the plan shows the call as `will be read during apply`, with the `Authorization` header as
`(sensitive value)`. The apply prints only the URL:

```text
module.loopproof_connector.data.http.registration[0]: Reading...
module.loopproof_connector.data.http.registration[0]: Read complete after 0s [id=https://api.loopproof.ai/connector/registrations]
```

Any answer but `200` fails the run:

```text
Error: Resource postcondition failed

LoopProof did not accept the connector registration (HTTP 401).
Paste the connector role ARN into LoopProof's onboarding instead:
arn:aws:iam::111122223333:role/loopproof-production-connector
Then remove registration_token from the module call and apply again.
```

The module doesn't retry: a retry that runs out ends with the provider's own error, without that message. A network
error fails the run with the provider's error; apply again, or paste `role_arn`.

## Tags

Every resource gets `created_by_module = "infrahouse/loopproof-connector/aws"` and
`loopproof_environment = <environment>`; the connector role also gets `module_version`. Add your own with the AWS
provider's `default_tags`.
