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
  `loopproof-<environment>-*` in `control_plane_account_id`, plus `sts:ExternalId` from `external_ids`), allowed
  `securityhub:GetFindings` and `securityhub:BatchUpdateFindings`, the latter limited by Deny statements on
  `securityhub:OCSFSyntaxPath/*` to status and comment;
- `loopproof-<environment>-findings`: an EventBridge rule for "Findings Imported V2" events by OCSF `severity_id`,
  targeting `event_bus_arn` through `loopproof-<environment>-forwarder`, which may only `events:PutEvents` there;
- with `registration_token` set, an `http` data source that POSTs the role ARN to `registration_url`.

### Interface contract

LoopProof's onboarding generates the module call, so the variable names (`environment`,
`control_plane_account_id`, `external_ids`, `event_bus_arn`, `registration_url`, `registration_token`,
`severities`) and outputs (`role_arn`, `role_name`, `event_rule_arn`, `registered`) are a contract. Don't rename
them without a major version.

### Credentials

`external_ids` and `registration_token` are credentials. Never put them in an output, a tag, a description, or a
validation message. The trust policy is wrapped in `sensitive()` because Terraform doesn't carry the variable's
sensitivity into `aws_iam_policy_document.json`. The tests check plan and apply output for both values.

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
probe roles `loopproof-pytest-probe` (matches the trust) and `outsider-pytest-probe` (doesn't).

| File | Covers |
|------|--------|
| `tests/test_module.py` | Install, outputs, ExternalId exposure, trust, permissions (IAM simulator), forwarding pattern and target |
| `tests/test_rotation.py` | `[old]` → `[old, new]` → `[new]` without a failed AssumeRole |
| `tests/test_registration.py` | POST against a local server on 127.0.0.1, refused registration, token not printed |
| `tests/test_validation.py` | Variable validation (plans `test_data/validation`, creates nothing) |

`test_rotation.py` takes about 20 minutes on purpose. After a trust policy change, STS refuses a newly added
ExternalId now and then for a few minutes (a value listed before and after is never refused), so each step waits
until its change has held for `SETTLE_SECONDS` without a refusal. Don't shorten it to the first success.

Tests write `terraform.tf` and `terraform.tfvars.json` into the `test_data` roots; both are gitignored.
`tests/data/findings-imported-v2.json` is the sample event.

## Version Management

`.bumpversion.cfg` tracks the version in `locals.tf`, `tests/conftest.py`, `README.md` and `docs/`. Use the
`make release-*` targets; don't bump by hand.

## Files Managed Externally

These files are managed by Terraform in the `github-control` repository; don't edit them here:
`.claude/CODING_STANDARD.md`, `hooks/`, `.terraform-docs.yml`, `cliff.toml`, and the workflows that say so in their
header.
