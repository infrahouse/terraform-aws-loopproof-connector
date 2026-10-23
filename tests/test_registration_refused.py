"""
A first registration that LoopProof refuses, as it refuses a token that registered nothing and has
expired: the apply fails with what to do, and once a new token is stored, the next plain apply
registers by itself, because the failed registration is tainted. One test, so that the steps run in
order.
"""

import re
import subprocess

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    REGISTRATION_TOKEN_PARAMETER,
    TEST_ENVIRONMENT,
    connector_applied,
    connector_tfvars,
    fill_parameters,
    new_external_id,
    new_registration_token,
    printed,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_refused_then_registered(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    registration_server,
    ssm_client,
):
    """A 401 fails the apply with the fill-a-new-token message; the next plain apply registers."""
    external_id = new_external_id()
    expired = new_registration_token()
    renewed = new_registration_token()
    registration_server.answer(401)
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(
        CONNECTOR_ROOT,
        connector_tfvars(aws_region, test_role_arn, registration_server.url),
    )

    try:
        with pytest.raises(subprocess.CalledProcessError) as refused:
            with connector_applied(
                CONNECTOR_ROOT,
                ssm_client,
                [external_id],
                expired,
                destroy_after=False,
            ):
                pass
        message = " ".join((refused.value.output + refused.value.stderr).split())

        # One call: a 4xx is never retried.
        assert len(registration_server.requests) == 1
        assert re.search(
            r"refused the connector registration: HTTP/[0-9.]+ 401\b", message
        )
        assert registration_server.message in message
        assert (
            "Get a new registration token in LoopProof and put it in the SSM parameter"
            f" arn:aws:ssm:{aws_region}:" in message
        )
        assert f":parameter{REGISTRATION_TOKEN_PARAMETER}, then apply again." in message
        assert f":role/loopproof-{TEST_ENVIRONMENT}-connector" in message
        assert f"Region: {aws_region}" in message
        assert expired not in message
        assert external_id not in message

        # A new token, and LoopProof accepts it: the plain apply replaces the tainted registration.
        fill_parameters(ssm_client, registration_token=renewed)
        registration_server.answer(200)
        log = terraform_check(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
        assert "is tainted, so must be replaced" in log
        assert len(registration_server.requests) == 2
        assert (
            registration_server.requests[1]["headers"]["Authorization"]
            == f"Bearer {renewed}"
        )
        assert renewed not in log

        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert result.returncode == 0, printed(result)
        assert len(registration_server.requests) == 2
    finally:
        if not keep_after:
            terraform_check(CONNECTOR_ROOT, "destroy", "-input=false", "-auto-approve")
