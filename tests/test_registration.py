"""
Self-registration against a stand-in for LoopProof's API on 127.0.0.1.
The "no token, no request" case runs with the plain install in test_module.py.
"""

import json
import re

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    REGISTRATION_PATH,
    TEST_ENVIRONMENT,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_registration(
    aws_provider_version, aws_region, test_role_arn, keep_after, registration_server
):
    """One POST with the token and the role ARN; the token shows in no plan or apply output."""
    token = new_registration_token()
    external_id = new_external_id()
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(
        CONNECTOR_ROOT,
        connector_tfvars(
            aws_region, test_role_arn, [external_id], registration_server.url, token
        ),
    )

    with connector_applied(CONNECTOR_ROOT, destroy_after=not keep_after) as (
        outputs,
        log,
    ):
        assert len(registration_server.requests) == 1
        request = registration_server.requests[0]
        assert request["method"] == "POST"
        assert request["path"] == REGISTRATION_PATH
        assert request["headers"]["Authorization"] == f"Bearer {token}"
        assert request["headers"]["Content-Type"] == "application/json"
        assert json.loads(request["body"]) == {"role_arn": outputs["role_arn"]}
        assert outputs["registered"] is True

        assert token not in log
        assert external_id not in log
        # On the first apply the call waits for the role; the plan shows the header masked.
        assert re.search(r'"Authorization"\s+=\s+\(sensitive value\)', log)

        # A later plan with the token still set calls again, and LoopProof answers 200 to the repeat.
        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert result.returncode == 0, "the plan after the registration isn't empty"
        assert len(registration_server.requests) == 2
        assert registration_server.requests[1]["body"] == request["body"]
        assert token not in result.stdout + result.stderr


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_registration_refused(
    aws_provider_version, aws_region, test_role_arn, keep_after, registration_server
):
    """Any answer but 200 fails the apply, and the error tells the tenant to paste the role ARN."""
    token = new_registration_token()
    external_id = new_external_id()
    registration_server.status = 401
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(
        CONNECTOR_ROOT,
        connector_tfvars(
            aws_region, test_role_arn, [external_id], registration_server.url, token
        ),
    )

    try:
        terraform_check(CONNECTOR_ROOT, "init", "-input=false")
        result = terraform(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
        printed = result.stdout + result.stderr
        # Terraform wraps long error messages.
        message = " ".join(printed.split())

        assert result.returncode != 0
        assert len(registration_server.requests) == 1
        assert (
            "LoopProof did not accept the connector registration (HTTP 401)." in message
        )
        assert (
            "Paste the connector role ARN into LoopProof's onboarding instead:"
            in message
        )
        assert f":role/loopproof-{TEST_ENVIRONMENT}-connector" in message
        assert (
            "remove registration_token from the module call and apply again" in message
        )
        assert token not in printed
        assert external_id not in printed
    finally:
        if not keep_after:
            # Without the token, destroy makes no call.
            write_tfvars(
                CONNECTOR_ROOT,
                connector_tfvars(
                    aws_region, test_role_arn, [external_id], registration_server.url
                ),
            )
            terraform_check(CONNECTOR_ROOT, "destroy", "-input=false", "-auto-approve")
