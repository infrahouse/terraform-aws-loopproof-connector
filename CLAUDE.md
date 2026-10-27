# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First Steps

**Your first tool call in this repository MUST be reading .claude/CODING_STANDARD.md.
Do not read any other files, search, or take any actions until you have read it.**
This contains InfraHouse's comprehensive coding standards for Terraform, Python, and general formatting rules.

## Module Overview

`terraform-aws-loopproof-connector` is the tenant side of LoopProof, which turns AWS Security Hub v2 findings into
Linear tickets. Tenants install it in the account where Security Hub collects findings, in its home Region.
It creates:

- `loopproof-<environment>-connector`: a role the control plane assumes (`aws:PrincipalArn` matching
  `loopproof-<environment>-*` in `control_plane_account_id`, plus `sts:ExternalId` from the ExternalIds
  parameter, below), allowed
  `securityhub:GetFindings` and `securityhub:BatchUpdateFindings` (its policy `security-hub-findings`), the latter
  limited by Deny statements on `securityhub:OCSFSyntaxPath/*` to status and comment; and two reads of resource tags,
  for the tags LoopProof derives from a related resource, such as an ECR image's repository (IH-120):
  - `ecr:ListTagsForResource` on `arn:<partition>:ecr:*:<account>:repository/*`, every repository of the account in
    every Region (`ecr-repository-tags`). `tag:GetResources` would serve too, but takes no resource ARN and reads
    every tagged resource's tags;
  - `config:SelectAggregateResourceConfig` on `arn:<partition>:config:<module's Region>:<account>:config-aggregator/*`
    (`config-aggregator-query`), for AWS Control Tower's Config aggregator in Audit,
    `aws-controltower-GuardrailsComplianceAggregator`, which LoopProof queries by its name. IAM names an aggregator
    by an ARN that ends in a generated ID, so the grant covers every aggregator there, and matches nothing where there
    is none: no input and no lookup (Aleks, 2026-10-27, over an opt-in exact-ARN lookup through Cloud Control);
- `loopproof-<environment>-findings`: an EventBridge rule for "Findings Imported V2" events by OCSF `severity_id`,
  and, when `excluded_accounts` isn't empty, `anything-but` those accounts on the finding's `cloud.account.uid`,
  targeting `event_bus_arn` through `loopproof-<environment>-forwarder`, which may only `events:PutEvents` there;
- `/loopproof/<environment>/excluded-accounts`: a standard `String` SSM parameter, always created, holding
  `excluded_accounts` sorted as JSON (`[]` when empty), which the connector role may `ssm:GetParameter` (its policy
  `excluded-accounts-parameter`) and nothing else in SSM. LoopProof reads it at onboarding and daily; a
  registration token sets the role only while the tenant is provisional, and the list changes after that;
- `terraform_data.registration`, keyed on the role's ARN, whose `local-exec` runs `/bin/sh files/register.sh` once,
  when the resource is created: on the apply that creates the role, when the role is replaced, and with
  `terraform apply -replace`. The script POSTs `{"role_arn": ..., "region": ...}` to `registration_url` with `curl`,
  the token from the token parameter in `Authorization`, retrying connection errors and 5xx, never a 4xx. A failure
  fails the apply and taints the resource, so the next apply calls again. `region` is the AWS provider's Region,
  where the tenant applies the module: LoopProof reads the tenant's Security Hub there, and an IAM ARN carries no
  Region. What a failure tells the tenant to do depends on whether LoopProof has proven the account, which the
  script can't see, so its messages say both: a new token comes from LoopProof's onboarding before and from the
  Settings page after, where an admin mints one that registers only the tenant's role; and the role's ARN and
  Region, which every failure prints, are a paste into onboarding only before (`tests/test_register_script.py`).

The tenant's root creates two SSM SecureString parameters, `/loopproof/<environment>/external-ids` (a JSON list) and
`/loopproof/<environment>/registration-token`, with the write-only placeholder `unset` (`value_wo`, Terraform 1.11),
and passes their ARNs ("Part 1" in the docs; `test_data/connector` does it as the README says). The module reads the
ExternalIds with `data "aws_ssm_parameter"` (`external_ids.tf`), whose postconditions refuse the placeholder, then
anything but a JSON list of one or two ExternalIds, before `local.external_ids` decodes it; and the token with
`ephemeral "aws_ssm_parameter"` (`registration.tf`). On a new root's first apply, both ARNs are unknown at plan, so
both reads wait for the parameters, and the run stops at the placeholder: apply, fill, apply.

### Interface contract

LoopProof's onboarding generates the module call, so the variable names (`environment`,
`control_plane_account_id`, `external_ids_parameter_arn`, `registration_token_parameter_arn`, `event_bus_arn`,
`registration_url`, `severities`, `excluded_accounts`) and outputs (`role_arn`, `region`, `role_name`,
`event_rule_arn`, `excluded_accounts_parameter`) are a contract. Don't rename them without a major version. So are:

- the registration request body's fields, `role_arn` and `region`, which LoopProof's `POST /connector/registrations`
  reads, and the token in `Authorization: Bearer`;
- the ExternalIds parameter's value, a JSON list of one or two ExternalIds, and the placeholder `unset` that both
  parameters hold until the tenant fills them, which LoopProof's generated Part 1 creates;
- the excluded accounts' parameter, its name and its value, a JSON list of account IDs, which LoopProof reads with
  the connector role;
- the reads LoopProof calls with the connector role: `ListTagsForResource` on a repository's ARN, and
  `SelectAggregateResourceConfig` with the aggregator's name, `aws-controltower-GuardrailsComplianceAggregator`.

0.3.0's `external_ids` and `registration_token` inputs and `registered` output went in IH-114's major release.

With `excluded_accounts` empty, the rule's pattern is exactly 0.2.0's, so upgrading changes no tenant's rule: keep it
so. `anything-but` with no values isn't a valid pattern anyway. The account filter, like the control plane's echo
filter, relies on one finding per event: EventBridge matches an array when any element matches.

### Credentials

The ExternalIds and the registration token are credentials, and neither is an input. Never put them in an output, a
tag, a description, or a message: the checks' messages name the parameter, never the value. The trust policy is
wrapped in `sensitive()` because Terraform doesn't carry the parameter value's sensitivity into
`aws_iam_policy_document.json`; never `nonsensitive()` it. The token stays ephemeral: it reaches `files/register.sh`
through the provisioner's `environment`, never its `command`, and `curl` through standard input, never an argument.
Terraform suppresses the provisioner's output because of it, but shows all of it in the error when the script fails,
so the script prints what to do and never the token, the request or `set -x`. The module uses no AWS CLI.

The ARN inputs aren't sensitive: the checks' messages must name the parameter, and Terraform hides any message that
holds a sensitive value. So Terraform prints a malformed ARN beside its validation error, as for any string input.

The tests check plan and apply output, the outputs, the state, a saved plan and a `TF_LOG=DEBUG` log for both values
(`test_bootstrap.py`). At DEBUG the AWS provider logs its reads' responses but an ephemeral resource's: the token
shows there only in the refresh of Part 1's parameter, which is the root's, not the module's.

## Commands

```bash
make bootstrap          # Install dependencies (pip) and git hooks
make lint               # yamllint, terraform fmt -check, black --check
make format             # terraform fmt -recursive && black tests
make test               # Run all tests (CI)
make test-keep          # Run tests, keep AWS resources (TEST_PATH, TEST_SELECTOR narrow it)
make test-clean         # Run tests, destroy resources
make release-minor      # Update CHANGELOG, bump version, tag (from main)
```

Example: `make test-clean TEST_PATH=tests/test_rotation.py`.

## Testing

Integration tests with `pytest-infrahouse`, in the InfraHouse test account (`TEST_ROLE`, default region
`us-west-2`). The test account plays the control plane: `test_data/connector` creates a bus in `us-west-1` and the
probe roles `loopproof-pytest-probe` (matches the trust) and `outsider-pytest-probe` (doesn't). It plays the tenant's
resources too: `test_data/connector` creates the ECR repository `loopproof-pytest-tagged`, with a tag, and a
stand-in for Control Tower's Config aggregator, by its name, over the test account and Region, which
`test_module.py` queries as the connector role.

| File | Covers |
|------|--------|
| `tests/test_bootstrap.py` | Apply, fill, apply without `-target`; both placeholders; the request; leaks |
| `tests/test_registration_refused.py` | A 401 on the first registration, its message, the tainted retry |
| `tests/test_registration.py` | No later call; `-replace`; a replaced role; retries; 4xx; no `curl` |
| `tests/test_register_script.py` | `files/register.sh` with a stand-in `curl`: token on stdin only (no AWS) |
| `tests/test_module.py` | Install, outputs, ExternalId exposure, trust, permissions, tag reads, forwarding, `[]` |
| `tests/test_excluded_accounts.py` | Two accounts excluded: pattern, matching, parameter, plan, reordering |
| `tests/test_excluded_accounts_change.py` | `[]` → `[account]` → `[]`, each in place, then an empty plan |
| `tests/test_rotation.py` | The parameter `[old]` → `[old, new]` → `[new]` without a failed AssumeRole |
| `tests/test_upgrade.py` | 1.0.1 from the registry, then this checkout: only the new policies are added |
| `tests/test_validation.py` | Inputs and the ExternalIds parameter's contents, at plan |

The connector tests install the tidy way, `connector_applied` in `conftest.py`: apply Part 1's parameters with
`-target`, fill them, apply everything, with a stand-in for LoopProof's registration API on 127.0.0.1
(`RegistrationServer`, which counts the calls and answers as told). Every install registers, so every connector test
runs the stand-in. `test_bootstrap.py` alone takes the first apply without `-target`.

Tests that change a deployment after its fixture applied it can't share a file with parametrized tests: pytest runs
the parametrized cases grouped by index, after the later tests of the file. Put such a sequence in one test, in a file
of its own, as `test_excluded_accounts_change.py` does.

`test_upgrade.py` installs `test_data/upgrade`, a tenant's root, at `UPGRADE_FROM_VERSION` from the registry, by
writing `main_override.tf` (gitignored) to swap the module's source, then removes it and plans this checkout: only
`ADDED` may be created, only the role's `module_version` tag may change, and nothing registers again. A change that
adds or changes a resource updates `ADDED`, or the test's other checks, and moves `UPGRADE_FROM_VERSION` to the
latest release. Don't name it `*MODULE_VERSION`: bumpversion would rewrite it.

`test_rotation.py` takes about 20 minutes on purpose. After a trust policy change, STS refuses a newly added
ExternalId now and then for a few minutes (a value listed before and after is never refused), so each step waits
until its change has held for `SETTLE_SECONDS` without a refusal. Don't shorten it to the first success.

Tests write `terraform.tf` and `terraform.tfvars.json` into the `test_data` roots; both are gitignored. The connector
root needs Terraform 1.11, for Part 1's `value_wo`. Every test takes the `aws-6` id, which `make test-clean`'s
default `TEST_SELECTOR` selects; `test_register_script.py` takes it without using it.
`tests/data/findings-imported-v2.json` is the sample event.

## Version Management

`.bumpversion.cfg` tracks the version in `locals.tf`, `tests/conftest.py`, `README.md` and `docs/`. Use the
`make release-*` targets; don't bump by hand.

## Files Managed Externally

These files are managed by Terraform in the `github-control` repository; don't edit them here:
`.claude/CODING_STANDARD.md`, `hooks/`, `.terraform-docs.yml`, `cliff.toml`, and the workflows that say so in their
header.
