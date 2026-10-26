"""
Input validation. Each case plans the module with one bad value, either an input or the contents of
the ExternalIds parameter; nothing is created but the two parameters the module reads, which the
tests create and delete themselves.
"""

import json
from typing import Any, Dict, Iterator, Optional

import pytest
from botocore.exceptions import ClientError

from tests.conftest import (
    CONTROL_TOWER_AGGREGATOR,
    PLACEHOLDER,
    VALIDATION_ROOT,
    new_external_id,
    new_registration_token,
    printed,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)

CONTROL_PLANE_ACCOUNT_ID = "123456789012"
EVENT_BUS_ARN = f"arn:aws:events:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:event-bus/loopproof-pytest-findings"
# Apart from the connector root's, which test_data/connector creates.
EXTERNAL_IDS_PARAMETER = "/loopproof/pytest-validation/external-ids"
REGISTRATION_TOKEN_PARAMETER = "/loopproof/pytest-validation/registration-token"
EXTERNAL_ID = new_external_id()
OTHER_EXTERNAL_ID = new_external_id()
BAD_EXTERNAL_ID = EXTERNAL_ID[:-1] + "!"
ARN_MESSAGE = "must be the ARN of an SSM parameter"
SHAPE_MESSAGE = "must hold a JSON list of one ExternalId, or two during a rotation"

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
    # Terraform prints a string input's value beside the failed check, as for any input that isn't
    # sensitive, so these cases check the message only; the module's message doesn't repeat the value.
    (
        "external-ids-arn-a-name",
        {"external_ids_parameter_arn": "/loopproof/pytest/external-ids"},
        f"external_ids_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "external-ids-arn-secret",
        {
            "external_ids_parameter_arn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:loopproof-abcdef"
        },
        f"external_ids_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "token-arn-a-document",
        {
            "registration_token_parameter_arn": "arn:aws:ssm:us-west-2:123456789012:document/loopproof"
        },
        f"registration_token_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "token-arn-empty",
        {"registration_token_parameter_arn": ""},
        f"registration_token_parameter_arn {ARN_MESSAGE}",
        None,
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
    # The messages name the input without echoing the bad value.
    (
        "excluded-account-short",
        {"excluded_accounts": ["98765432101"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "98765432101",
    ),
    (
        "excluded-account-dashes",
        {"excluded_accounts": ["9876-5432-1012"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "9876-5432-1012",
    ),
    (
        "excluded-account-letters",
        {"excluded_accounts": ["98765432101x"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "98765432101x",
    ),
    (
        "excluded-accounts-repeated",
        {"excluded_accounts": ["987654321012", "987654321012"]},
        "excluded_accounts must not list an account ID twice",
        "987654321012",
    ),
]

# Contents of the ExternalIds parameter that the module refuses, at plan, without echoing them.
EXTERNAL_IDS_CASES = [
    ("placeholder", PLACEHOLDER, "still holds the placeholder"),
    ("not-json", EXTERNAL_ID, SHAPE_MESSAGE),
    ("json-string", json.dumps(EXTERNAL_ID), SHAPE_MESSAGE),
    ("json-object", json.dumps({"external_id": EXTERNAL_ID}), SHAPE_MESSAGE),
    ("empty-list", "[]", SHAPE_MESSAGE),
    (
        "three",
        json.dumps([EXTERNAL_ID, OTHER_EXTERNAL_ID, new_external_id()]),
        SHAPE_MESSAGE,
    ),
    ("short", json.dumps([EXTERNAL_ID[:42]]), SHAPE_MESSAGE),
    ("bad-character", json.dumps([BAD_EXTERNAL_ID]), SHAPE_MESSAGE),
    ("repeated", json.dumps([EXTERNAL_ID, EXTERNAL_ID]), SHAPE_MESSAGE),
    ("not-a-string", json.dumps([EXTERNAL_ID, 7]), SHAPE_MESSAGE),
]


@pytest.fixture(scope="module")
def parameters(boto3_session, aws_region) -> Iterator[Dict[str, Any]]:
    """
    The two parameters the module reads, in the provider's Region, filled with valid values.
    """
    ssm_client = boto3_session.client("ssm", region_name=aws_region)
    values = {
        EXTERNAL_IDS_PARAMETER: json.dumps([EXTERNAL_ID]),
        REGISTRATION_TOKEN_PARAMETER: new_registration_token(),
    }
    arns = {}
    try:
        for name, value in values.items():
            ssm_client.put_parameter(
                Name=name, Value=value, Type="SecureString", Overwrite=True
            )
            arns[name] = ssm_client.get_parameter(Name=name)["Parameter"]["ARN"]
        yield {"ssm_client": ssm_client, "arns": arns}
    finally:
        ssm_client.delete_parameters(Names=list(values))


def store_external_ids(parameters: Dict[str, Any], value: str) -> None:
    """
    :param parameters: The ``parameters`` fixture.
    :param value: What to put in the ExternalIds parameter.
    """
    parameters["ssm_client"].put_parameter(
        Name=EXTERNAL_IDS_PARAMETER, Value=value, Type="SecureString", Overwrite=True
    )


def tfvars(
    aws_region: str,
    test_role_arn: Optional[str],
    parameters: Dict[str, Any],
    **overrides: Any,
) -> Dict[str, Any]:
    """
    Build valid inputs for the validation root module, with some values replaced.

    :param aws_region: Region for the AWS provider.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param parameters: The ``parameters`` fixture.
    :param overrides: Inputs to replace.
    :return: Variable names and values.
    """
    values = {
        "region": aws_region,
        "role_arn": test_role_arn,
        "environment": "pytest",
        "control_plane_account_id": CONTROL_PLANE_ACCOUNT_ID,
        "external_ids_parameter_arn": parameters["arns"][EXTERNAL_IDS_PARAMETER],
        "registration_token_parameter_arn": parameters["arns"][
            REGISTRATION_TOKEN_PARAMETER
        ],
        "event_bus_arn": EVENT_BUS_ARN,
        "registration_url": "https://api.staging.loopproof.ai/connector/registrations",
        "severities": None,
        "excluded_accounts": None,
        "enable_control_tower_aggregator_query": None,
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
    "overrides, external_ids",
    [
        ({}, [EXTERNAL_ID]),
        ({}, [EXTERNAL_ID, OTHER_EXTERNAL_ID]),
        (
            {"registration_url": "http://127.0.0.1:8080/connector/registrations"},
            [EXTERNAL_ID],
        ),
        (
            {"registration_url": "http://localhost/connector/registrations"},
            [EXTERNAL_ID],
        ),
        (
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
            [EXTERNAL_ID],
        ),
        ({"environment": "production-eu-1"}, [EXTERNAL_ID]),
        ({"excluded_accounts": []}, [EXTERNAL_ID]),
        ({"excluded_accounts": ["987654321012", "210987654321"]}, [EXTERNAL_ID]),
        # Off, the module doesn't look for the aggregator, which the test account doesn't have.
        ({"enable_control_tower_aggregator_query": False}, [EXTERNAL_ID]),
    ],
    ids=[
        "defaults",
        "two-external-ids",
        "url-loopback",
        "url-localhost",
        "all-severities",
        "environment-hyphens",
        "excluded-accounts-empty",
        "excluded-accounts-two",
        "aggregator-query-off",
    ],
)
def test_valid_inputs(
    validation_root, parameters, aws_region, test_role_arn, overrides, external_ids
):
    """Valid inputs plan cleanly, so the failures below come from the bad value alone."""
    store_external_ids(parameters, json.dumps(external_ids))
    write_tfvars(
        validation_root, tfvars(aws_region, test_role_arn, parameters, **overrides)
    )
    log = terraform_check(validation_root, "plan", "-input=false")
    for external_id in external_ids:
        assert external_id not in log


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "overrides, message, secret",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_invalid_inputs(
    validation_root, parameters, aws_region, test_role_arn, overrides, message, secret
):
    """A bad value fails the plan with a message that names the problem, without echoing secrets."""
    store_external_ids(parameters, json.dumps([EXTERNAL_ID]))
    write_tfvars(
        validation_root, tfvars(aws_region, test_role_arn, parameters, **overrides)
    )
    result = terraform(validation_root, "plan", "-input=false")

    assert result.returncode != 0
    assert message in printed(result)
    if secret is not None:
        assert secret not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
def test_aggregator_query_without_aggregator(
    validation_root, parameters, boto3_session, aws_region, test_role_arn
):
    """
    With the aggregator query on, the plan fails where Control Tower's aggregator isn't, and the error
    names it. Off, the same account plans cleanly (``aggregator-query-off`` above).
    """
    config = boto3_session.client("config", region_name=aws_region)
    with pytest.raises(ClientError) as err:
        config.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[CONTROL_TOWER_AGGREGATOR]
        )
    assert (
        err.value.response["Error"]["Code"] == "NoSuchConfigurationAggregatorException"
    ), "a stand-in aggregator is left from test_config_aggregator.py; delete it"

    store_external_ids(parameters, json.dumps([EXTERNAL_ID]))
    write_tfvars(
        validation_root,
        tfvars(
            aws_region,
            test_role_arn,
            parameters,
            enable_control_tower_aggregator_query=True,
        ),
    )
    result = terraform(validation_root, "plan", "-input=false")

    assert result.returncode != 0
    assert CONTROL_TOWER_AGGREGATOR in printed(result)
    assert "was not found" in printed(result)


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "value, message",
    [case[1:] for case in EXTERNAL_IDS_CASES],
    ids=[case[0] for case in EXTERNAL_IDS_CASES],
)
def test_invalid_external_ids(
    validation_root, parameters, aws_region, test_role_arn, value, message
):
    """
    Bad contents of the ExternalIds parameter fail the plan with one message, which names the
    parameter and doesn't echo what it holds. The placeholder is caught before the JSON is decoded.
    """
    store_external_ids(parameters, value)
    write_tfvars(validation_root, tfvars(aws_region, test_role_arn, parameters))
    result = terraform(validation_root, "plan", "-input=false")
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert f"{parameters['arns'][EXTERNAL_IDS_PARAMETER]} {message}" in printed(result)
    assert output.count("Error:") == 1, output
    for external_id in [
        EXTERNAL_ID,
        EXTERNAL_ID[:42],
        BAD_EXTERNAL_ID,
        OTHER_EXTERNAL_ID,
    ]:
        assert external_id not in output
