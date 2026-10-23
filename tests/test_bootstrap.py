"""
The install as a tenant does it, in one root holding Part 1's parameters and the module, without
``-target``: apply, which creates the parameters and stops at the ExternalIds' placeholder; fill the
ExternalIds and apply, which creates the connector and stops at the token's placeholder; store the
token and apply, which registers. Neither value shows in anything Terraform printed, and the token is
in no state file or saved plan. One test, so that the steps run in order.
"""

import json
import os
import re
from os import path as osp
from typing import Any, Dict, List, Tuple

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    EXTERNAL_IDS_PARAMETER,
    PLACEHOLDER,
    REGISTRATION_PATH,
    REGISTRATION_TOKEN_PARAMETER,
    STATE_FILES,
    TEST_ENVIRONMENT,
    connector_tfvars,
    fill_parameters,
    new_external_id,
    new_registration_token,
    printed,
    state_text,
    terraform,
    terraform_check,
    terraform_outputs,
    write_terraform_tf,
    write_tfvars,
)


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_bootstrap(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    registration_server,
    ssm_client,
    iam_client,
    tmp_path,
):
    """Apply, fill, apply: the connector registers once both parameters hold their values."""
    external_ids = [new_external_id()]
    token = new_registration_token()
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(
        CONNECTOR_ROOT,
        connector_tfvars(aws_region, test_role_arn, registration_server.url),
    )
    logs = []

    try:
        terraform_check(CONNECTOR_ROOT, "init", "-input=false")

        # The first apply: both parameter ARNs are unknown at plan, so the module's reads wait for
        # the parameters, and the ExternalIds' check stops the run before the connector exists.
        first = terraform(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
        logs.append(first.stdout + first.stderr)
        message = printed(first)
        assert first.returncode != 0
        assert "ParameterNotFound" not in message
        assert (
            f":parameter{EXTERNAL_IDS_PARAMETER} still holds the placeholder" in message
        )
        # The unset check comes before the jsondecode, so the decoding never fails on the placeholder.
        assert "jsondecode" not in message
        assert registration_server.requests == []
        for name in [EXTERNAL_IDS_PARAMETER, REGISTRATION_TOKEN_PARAMETER]:
            parameter = ssm_client.get_parameter(Name=name, WithDecryption=True)
            assert parameter["Parameter"]["Type"] == "SecureString"
            assert parameter["Parameter"]["Value"] == PLACEHOLDER
        with pytest.raises(iam_client.exceptions.NoSuchEntityException):
            iam_client.get_role(RoleName=f"loopproof-{TEST_ENVIRONMENT}-connector")

        # The ExternalIds alone: the connector is created, and the registration stops at the token's
        # placeholder without calling LoopProof.
        fill_parameters(ssm_client, external_ids=external_ids)
        second = terraform(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
        logs.append(second.stdout + second.stderr)
        message = printed(second)
        assert second.returncode != 0
        assert (
            f":parameter{REGISTRATION_TOKEN_PARAMETER} still holds the placeholder"
            in message
        )
        assert registration_server.requests == []

        # The token: the next plain apply registers, the failed registration being tainted.
        fill_parameters(ssm_client, registration_token=token)
        # Terraform appends both commands' debug logs to the file.
        debug_log = str(tmp_path / "terraform-debug.log")
        debug_env = {**os.environ, "TF_LOG": "DEBUG", "TF_LOG_PATH": debug_log}
        plan = terraform_check(
            CONNECTOR_ROOT, "plan", "-input=false", "-out=tfplan", env=debug_env
        )
        logs.append(plan)
        assert "is tainted, so must be replaced" in plan
        saved_plan = terraform_check(CONNECTOR_ROOT, "show", "-json", "tfplan")
        logs.append(
            terraform_check(
                CONNECTOR_ROOT, "apply", "-input=false", "tfplan", env=debug_env
            )
        )
        outputs = terraform_outputs(CONNECTOR_ROOT)
        raw_outputs = terraform_check(CONNECTOR_ROOT, "output", "-json")

        assert len(registration_server.requests) == 1
        request = registration_server.requests[0]
        assert request["method"] == "POST"
        assert request["path"] == REGISTRATION_PATH
        assert request["headers"]["Authorization"] == f"Bearer {token}"
        assert request["headers"]["Content-Type"] == "application/json"
        # The Region is the tenant's provider's, where LoopProof reads Security Hub, not the bus's.
        assert json.loads(request["body"]) == {
            "role_arn": outputs["role_arn"],
            "region": aws_region,
        }

        # The leaks. Neither value in anything Terraform printed, the outputs included.
        for value in [token, *external_ids]:
            for log in logs:
                assert value not in log
            assert value not in raw_outputs
        # At DEBUG, the AWS provider logs the responses of its reads, but an ephemeral resource's. So the
        # token shows only where it refreshes Part 1's parameter, which reads it decrypted: never from the
        # module's read of the token, and never from Terraform itself, such as the provisioner's
        # environment. The ExternalIds show there too, in the module's read, and in the role's trust policy.
        root_refresh = ("resource", "aws_ssm_parameter", "ReadResource")
        assert set(debug_log_readers(debug_log, token)) == {root_refresh}
        assert set(debug_log_readers(debug_log, external_ids[0])) == {
            root_refresh,
            ("data_source", "aws_ssm_parameter", "ReadDataSource"),
            ("resource", "aws_iam_role", "ReadResource"),
        }
        # The token in no state file and no saved plan; the ExternalIds are in the state, in the
        # connector's trust policy, as the charter accepts.
        assert token not in state_text(CONNECTOR_ROOT)
        assert token not in saved_plan
        with open(osp.join(CONNECTOR_ROOT, STATE_FILES[0]), encoding="utf-8") as fp:
            state = json.load(fp)
        holding = {
            resource_address(resource)
            for resource in state["resources"]
            for instance in resource["instances"]
            if external_ids[0] in json.dumps(instance["attributes"])
        }
        assert holding == {
            "module.connector.data.aws_ssm_parameter.external_ids",
            "module.connector.data.aws_iam_policy_document.connector_trust",
            "module.connector.aws_iam_role.connector",
        }

        # Part 1's parameters keep no value in the state: the placeholder is write-only.
        for resource in state["resources"]:
            if resource["type"] == "aws_ssm_parameter" and "module" not in resource:
                attributes = resource["instances"][0]["attributes"]
                assert attributes["has_value_wo"] is True
                assert attributes["value"] in ("", None)
    finally:
        if not keep_after:
            terraform_check(CONNECTOR_ROOT, "destroy", "-input=false", "-auto-approve")
            for name in [EXTERNAL_IDS_PARAMETER, REGISTRATION_TOKEN_PARAMETER]:
                assert not ssm_client.describe_parameters(
                    ParameterFilters=[
                        {"Key": "Name", "Option": "Equals", "Values": [name]}
                    ]
                )["Parameters"], f"destroy left {name}"


def resource_address(resource: Dict[str, Any]) -> str:
    """
    :param resource: A resource from a state file.
    :return: Its address, such as ``module.connector.data.aws_ssm_parameter.external_ids``.
    """
    parts = [resource["module"]] if "module" in resource else []
    if resource["mode"] == "data":
        parts.append("data")
    return ".".join([*parts, resource["type"], resource["name"]])


def debug_log_readers(path: str, value: str) -> List[Tuple[str, str, str]]:
    """
    Find who logged a value in a Terraform debug log.

    :param path: The log, from ``TF_LOG=DEBUG``.
    :param value: What to look for.
    :return: For each log entry holding the value: the kind of object whose call logged it
        (``resource``, ``data_source`` or ``ephemeral_resource``), its type, and the provider's RPC; empty
        strings where the entry names none, as Terraform's own entries don't.
    """
    with open(path, encoding="utf-8") as fp:
        entries = re.split(r"\n(?=\d{4}-\d\d-\d\dT)", fp.read())
    readers = []
    for entry in entries:
        if value not in entry:
            continue
        kind = re.search(
            r"tf_(resource|data_source|ephemeral_resource)_type=(\S+)", entry
        )
        rpc = re.search(r"tf_rpc=(\S+)", entry)
        readers.append(
            (
                kind.group(1) if kind else "",
                kind.group(2) if kind else "",
                rpc.group(1) if rpc else "",
            )
        )
    return readers
