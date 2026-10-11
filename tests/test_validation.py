"""
Input validation. Each case plans the module with one bad value; nothing is created.
"""

from typing import Any, Dict, Optional

import pytest

from tests.conftest import (
    VALIDATION_ROOT,
    new_external_id,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)

CONTROL_PLANE_ACCOUNT_ID = "123456789012"
EVENT_BUS_ARN = f"arn:aws:events:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:event-bus/loopproof-pytest-findings"
EXTERNAL_ID = new_external_id()
OTHER_EXTERNAL_ID = new_external_id()
BAD_EXTERNAL_ID = EXTERNAL_ID[:-1] + "!"
BAD_TOKEN = "tok_" + new_external_id()

CASES = [
    (
        "account-id-short",
        {"control_plane_account_id": "12345"},
        "must be a 12-digit AWS account ID",
        None,
    ),
    (
        "account-id-letters",
        {"control_plane_account_id": "12345678901a"},
        "must be a 12-digit AWS account ID",
        None,
    ),
    (
        "external-id-short",
        {"external_ids": [EXTERNAL_ID[:42]]},
        "exactly 43 characters",
        EXTERNAL_ID[:42],
    ),
    (
        "external-id-bad-char",
        {"external_ids": [BAD_EXTERNAL_ID]},
        "exactly 43 characters",
        BAD_EXTERNAL_ID,
    ),
    (
        "external-ids-three",
        {"external_ids": [EXTERNAL_ID, OTHER_EXTERNAL_ID, new_external_id()]},
        "must hold one ExternalId, or two during a rotation",
        EXTERNAL_ID,
    ),
    (
        "external-ids-none",
        {"external_ids": []},
        "must hold one ExternalId, or two during a rotation",
        None,
    ),
    (
        "external-ids-repeated",
        {"external_ids": [EXTERNAL_ID, EXTERNAL_ID]},
        "must not repeat a value",
        EXTERNAL_ID,
    ),
    (
        "token-prefix",
        {"registration_token": BAD_TOKEN},
        'must start with "lprt_"',
        BAD_TOKEN,
    ),
    (
        "token-whitespace",
        {"registration_token": "lprt_abc def"},
        'must start with "lprt_"',
        "lprt_abc def",
    ),
    (
        "url-http",
        {"registration_url": "http://api.staging.loopproof.ai/connector/registrations"},
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "url-http-localhost-lookalike",
        {"registration_url": "http://localhost.example.com/connector/registrations"},
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "url-credentials",
        {
            "registration_url": "https://user:secret@api.staging.loopproof.ai/connector/registrations"
        },
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "environment-uppercase",
        {"environment": "Staging"},
        "lowercase letters, digits or hyphens",
        None,
    ),
    (
        "event-bus-not-a-bus",
        {
            "event_bus_arn": f"arn:aws:sqs:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:loopproof"
        },
        "event_bus_arn must be an EventBridge event bus ARN",
        None,
    ),
    (
        "event-bus-other-account",
        {
            "event_bus_arn": "arn:aws:events:us-west-1:210987654321:event-bus/loopproof-pytest-findings"
        },
        f"must be a bus in the control-plane account {CONTROL_PLANE_ACCOUNT_ID}",
        None,
    ),
    (
        "severity-asff-label",
        {"severities": ["HIGH"]},
        "severities may only contain",
        None,
    ),
    (
        "severity-unknown-word",
        {"severities": ["High", "Severe"]},
        "severities may only contain",
        None,
    ),
    ("severities-empty", {"severities": []}, "must list at least one severity", None),
]


def tfvars(
    aws_region: str, test_role_arn: Optional[str], **overrides: Any
) -> Dict[str, Any]:
    """
    Build valid inputs for the validation root module, with some values replaced.

    :param aws_region: Region for the AWS provider.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param overrides: Inputs to replace.
    :return: Variable names and values.
    """
    values = {
        "region": aws_region,
        "role_arn": test_role_arn,
        "environment": "pytest",
        "control_plane_account_id": CONTROL_PLANE_ACCOUNT_ID,
        "external_ids": [EXTERNAL_ID],
        "event_bus_arn": EVENT_BUS_ARN,
        "registration_url": "https://api.staging.loopproof.ai/connector/registrations",
        "registration_token": None,
        "severities": None,
    }
    values.update(overrides)
    return values


@pytest.fixture(scope="module")
def validation_root(aws_provider_version):
    """The validation root module, initialized once."""
    write_terraform_tf(VALIDATION_ROOT, aws_provider_version)
    terraform_check(VALIDATION_ROOT, "init", "-input=false")
    return VALIDATION_ROOT


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"external_ids": [EXTERNAL_ID, OTHER_EXTERNAL_ID]},
        {"registration_url": "http://127.0.0.1:8080/connector/registrations"},
        {"registration_url": "http://localhost/connector/registrations"},
        {
            "severities": [
                "Unknown",
                "Informational",
                "Low",
                "Medium",
                "High",
                "Critical",
                "Fatal",
                "Other",
            ]
        },
        {"environment": "production-eu-1"},
    ],
    ids=[
        "defaults",
        "two-external-ids",
        "url-loopback",
        "url-localhost",
        "all-severities",
        "environment-hyphens",
    ],
)
def test_valid_inputs(validation_root, aws_region, test_role_arn, overrides):
    """Valid inputs plan cleanly, so the failures below come from the bad value alone."""
    write_tfvars(validation_root, tfvars(aws_region, test_role_arn, **overrides))
    terraform_check(validation_root, "plan", "-input=false")


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "overrides, message, secret",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_invalid_inputs(
    validation_root, aws_region, test_role_arn, overrides, message, secret
):
    """A bad value fails the plan with a message that names the problem, without echoing secrets."""
    write_tfvars(validation_root, tfvars(aws_region, test_role_arn, **overrides))
    result = terraform(validation_root, "plan", "-input=false")
    printed = result.stdout + result.stderr

    assert result.returncode != 0
    # Terraform wraps long error messages.
    assert message in " ".join(printed.split())
    if secret is not None:
        assert secret not in printed
