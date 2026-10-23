"""
The registration of an installed connector, against a stand-in for LoopProof's API on 127.0.0.1 that
counts the calls. The tests share one deployment, registered when the fixture installs it. Each test
that registers again starts from ``-replace``, so the tests don't depend on each other's order, and
none is parametrized: see "Testing" in CLAUDE.md.
"""

import os
import re
import subprocess
from typing import Any, Dict, Iterator, Optional

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    REGISTRATION_ADDRESS,
    REGISTRATION_ATTEMPTS,
    ROLE_ADDRESS,
    RegistrationServer,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    path_without,
    printed,
    registration_server_running,
    terraform,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
) -> Iterator[Dict[str, Any]]:
    """Install the connector, which registers once with the stand-in API."""
    ssm_client = boto3_session.client("ssm", region_name=aws_region)
    token = new_registration_token()
    with registration_server_running() as server:
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(
            CONNECTOR_ROOT, connector_tfvars(aws_region, test_role_arn, server.url)
        )
        with connector_applied(
            CONNECTOR_ROOT,
            ssm_client,
            [new_external_id()],
            token,
            destroy_after=not keep_after,
        ) as (outputs, log):
            assert len(server.requests) == 1
            yield {"server": server, "outputs": outputs, "token": token, "log": log}


def apply(
    *args: str, env: Optional[Dict[str, str]] = None
) -> subprocess.CompletedProcess:
    """
    Apply the connector root without asking.

    :param args: More arguments, such as ``-replace=<address>``.
    :param env: Environment for Terraform; the test's own when ``None``.
    :return: The finished process; it may have failed.
    """
    return terraform(
        CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve", *args, env=env
    )


def test_no_call_after_registration(connector):
    """A later plan is clean and a later apply changes nothing; neither calls LoopProof."""
    server: RegistrationServer = connector["server"]
    calls = len(server.requests)

    result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
    assert result.returncode == 0, printed(result)
    result = apply()
    assert result.returncode == 0, printed(result)
    assert "Resources: 0 added, 0 changed, 0 destroyed." in result.stdout
    assert len(server.requests) == calls


def test_replace_registers_again(connector):
    """terraform apply -replace on the registration makes one more call, and a 200 passes."""
    server: RegistrationServer = connector["server"]
    server.answer(200)
    calls = len(server.requests)

    result = apply(f"-replace={REGISTRATION_ADDRESS}")
    assert result.returncode == 0, printed(result)
    assert len(server.requests) == calls + 1
    assert server.requests[-1]["body"] == server.requests[0]["body"]
    assert connector["token"] not in result.stdout + result.stderr


def test_recreated_role_registers_again(connector):
    """A recreated connector role registers again, without -replace on the registration."""
    server: RegistrationServer = connector["server"]
    server.answer(200)
    calls = len(server.requests)

    result = apply(f"-replace={ROLE_ADDRESS}")
    assert result.returncode == 0, printed(result)
    assert len(server.requests) == calls + 1


def test_5xx_retried(connector):
    """A 5xx is retried, and the retry's 200 registers."""
    server: RegistrationServer = connector["server"]
    server.answer(503, 200)
    calls = len(server.requests)

    result = apply(f"-replace={REGISTRATION_ADDRESS}")
    assert result.returncode == 0, printed(result)
    assert len(server.requests) == calls + 2


def test_dropped_connection_retried(connector):
    """A connection closed without an answer is retried, and the retry's 200 registers."""
    server: RegistrationServer = connector["server"]
    server.answer(RegistrationServer.DROP, 200)
    calls = len(server.requests)

    result = apply(f"-replace={REGISTRATION_ADDRESS}")
    assert result.returncode == 0, printed(result)
    assert len(server.requests) == calls + 2


def test_5xx_until_attempts_run_out(connector, aws_region):
    """A 5xx on every attempt fails the apply after the last one, with the role ARN and Region to paste."""
    server: RegistrationServer = connector["server"]
    server.answer(502)
    calls = len(server.requests)

    result = apply(f"-replace={REGISTRATION_ADDRESS}")
    message = printed(result)
    assert result.returncode != 0
    assert len(server.requests) == calls + REGISTRATION_ATTEMPTS
    assert re.search(r"HTTP/[0-9.]+ 502\b", message)
    assert f"after {REGISTRATION_ATTEMPTS} attempts" in message
    assert connector["outputs"]["role_arn"] in message
    assert f"Region: {aws_region}" in message
    # LoopProof failed, not the token: the message doesn't ask for a new one.
    assert "Get a new registration token" not in message
    assert connector["token"] not in message


def test_4xx_not_retried(connector):
    """A 4xx fails at once, including 408 and 429, which curl's own --retry would retry."""
    server: RegistrationServer = connector["server"]
    for status in [401, 408, 429]:
        server.answer(status)
        calls = len(server.requests)

        result = apply(f"-replace={REGISTRATION_ADDRESS}")
        message = printed(result)
        assert result.returncode != 0
        assert len(server.requests) == calls + 1, status
        assert re.search(rf"HTTP/[0-9.]+ {status}\b", message)
        assert "Get a new registration token in LoopProof" in message
        assert connector["token"] not in message


def test_no_curl(connector, tmp_path):
    """Without curl on PATH, the registration fails with a plain message and calls nothing."""
    server: RegistrationServer = connector["server"]
    server.answer(200)
    calls = len(server.requests)
    env = {**os.environ, "PATH": path_without("curl", str(tmp_path))}

    result = apply(f"-replace={REGISTRATION_ADDRESS}", env=env)
    message = printed(result)
    assert result.returncode != 0
    assert "registers the connector role with curl, which isn't on PATH" in message
    assert len(server.requests) == calls
