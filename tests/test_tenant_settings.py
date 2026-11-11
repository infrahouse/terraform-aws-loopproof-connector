"""
The tenant's settings (IH-156), as LoopProof reads them: one SSM parameter, /loopproof/<environment>/tenant-settings,
always created, holding every setting as JSON, LoopProof's default for each the tenant leaves out. The connector role
reads it, and nothing more of it. The tests share one deployment, installed with the input left out; the last one
applies every setting changed. test_tenant_settings_change.py changes a setting and follows the parameter's versions.
"""

import json
import re
from typing import Any, Callable, Dict, Iterator, List

import pytest
from botocore.exceptions import ClientError

from tests.conftest import (
    CHANGED_TENANT_SETTINGS,
    CONNECTOR_ROOT,
    DEFAULT_TENANT_SETTINGS,
    DEFAULT_TENANT_SETTINGS_JSON,
    EXCLUDED_ACCOUNTS_PARAMETER,
    TENANT_SETTINGS_PARAMETER,
    TEST_ENVIRONMENT,
    THREAT_KIND,
    VULN_KIND,
    ConnectorProbe,
    as_list,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    policy_statements,
    registration_server_running,
    terraform,
    terraform_check,
    terraform_json,
    wait_for,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)

# CHANGED_TENANT_SETTINGS written another way: in another order, some numbers as strings or with a fraction of
# zero, and the quiet window as -0. The module publishes the same bytes for it.
CHANGED_WRITTEN_ANOTHER_WAY = {
    "review_due_before_days": "30",
    "ticket_budget_per_hour": 50.0,
    "quiet_window_days": -0.0,
    "thresholds": {VULN_KIND: "High", THREAT_KIND: "Medium"},
    "sla_target_days": {
        VULN_KIND: {"low": "180", "medium": 60.0, "high": 30, "critical": "15"},
        THREAT_KIND: {"low": 120, "medium": "45", "high": 10.0, "critical": 3},
    },
}


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
) -> Iterator[Dict[str, Any]]:
    """Install the connector with the settings left out."""
    external_id = new_external_id()
    with registration_server_running() as server:
        tfvars = connector_tfvars(aws_region, test_role_arn, server.url)
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(CONNECTOR_ROOT, tfvars)
        with connector_applied(
            CONNECTOR_ROOT,
            boto3_session.client("ssm", region_name=aws_region),
            [external_id],
            new_registration_token(),
            destroy_after=not keep_after,
        ) as (outputs, log):
            yield {
                "outputs": outputs,
                "log": log,
                "tfvars": tfvars,
                "external_id": external_id,
                "server": server,
            }


def test_defaults_published(connector, ssm_client):
    """
    With the input left out, the parameter exists and holds LoopProof's defaults, every setting, as exactly
    these bytes: a standard String parameter, not encrypted with a KMS key, named by the output.
    """
    assert connector["outputs"]["tenant_settings_parameter"] == (
        TENANT_SETTINGS_PARAMETER
    )
    parameter = ssm_client.get_parameter(Name=TENANT_SETTINGS_PARAMETER)["Parameter"]
    assert parameter["Type"] == "String"
    assert parameter["Value"] == DEFAULT_TENANT_SETTINGS_JSON
    assert json.loads(parameter["Value"]) == DEFAULT_TENANT_SETTINGS
    assert terraform_json(DEFAULT_TENANT_SETTINGS) == DEFAULT_TENANT_SETTINGS_JSON

    described = ssm_client.describe_parameters(
        ParameterFilters=[
            {"Key": "Name", "Option": "Equals", "Values": [TENANT_SETTINGS_PARAMETER]}
        ]
    )["Parameters"]
    assert len(described) == 1
    assert described[0]["Tier"] == "Standard"
    assert "KeyId" not in described[0]


def test_parameter_tags(connector, ssm_client):
    """The parameter carries the module's tags, as the excluded accounts' does."""
    tags = {
        tag["Key"]: tag["Value"]
        for tag in ssm_client.list_tags_for_resource(
            ResourceType="Parameter", ResourceId=TENANT_SETTINGS_PARAMETER
        )["TagList"]
    }
    assert tags["created_by_module"] == "infrahouse/loopproof-connector/aws"
    assert tags["loopproof_environment"] == TEST_ENVIRONMENT


def test_plan_shows_settings(connector):
    """The plan shows every setting it publishes: the settings aren't secret, and the pull request approves them."""
    published = re.search(
        r'name\s+=\s+"' + re.escape(TENANT_SETTINGS_PARAMETER) + '"', connector["log"]
    )
    assert published, f"the plan doesn't show {TENANT_SETTINGS_PARAMETER}"
    for setting in [
        "sla_target_days",
        "thresholds",
        "quiet_window_days",
        "ticket_budget_per_hour",
        "review_due_before_days",
    ]:
        assert re.search(rf"\b{setting}\s+=", connector["log"]), setting


def test_tenant_settings_policy(connector, iam_client, ssm_client):
    """The connector role's policy tenant-settings-parameter allows GetParameter on the parameter, and nothing else."""
    statements = policy_statements(
        iam_client.get_role_policy(
            RoleName=connector["outputs"]["role_name"],
            PolicyName="tenant-settings-parameter",
        )["PolicyDocument"]
    )
    parameter_arn = ssm_client.get_parameter(Name=TENANT_SETTINGS_PARAMETER)[
        "Parameter"
    ]["ARN"]

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["ssm:GetParameter"]
    assert as_list(statements[0]["Resource"]) == [parameter_arn]
    assert "Condition" not in statements[0]


def test_connector_reads_settings(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof reads the parameter with GetParameter, with no KMS permission; it can't
    write it, read its history, or read it another way. A role the trust doesn't match can't assume the
    connector role to read it.
    """
    outputs = connector["outputs"]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    values: List[str] = []

    def read() -> bool:
        try:
            ssm = probe.session(
                outputs["probe_role_arn"], connector["external_id"]
            ).client("ssm")
            values.append(
                ssm.get_parameter(Name=TENANT_SETTINGS_PARAMETER)["Parameter"]["Value"]
            )
        except ClientError as err:
            # STS answers AccessDenied, SSM AccessDeniedException, until IAM has the change.
            if err.response["Error"]["Code"] in (
                "AccessDenied",
                "AccessDeniedException",
            ):
                return False
            raise
        return True

    wait_for(read, "the connector role can read the tenant's settings")
    assert values[-1] == DEFAULT_TENANT_SETTINGS_JSON

    ssm = probe.session(outputs["probe_role_arn"], connector["external_id"]).client(
        "ssm"
    )
    refused: List[Callable[[], Any]] = [
        lambda: ssm.get_parameters(Names=[TENANT_SETTINGS_PARAMETER]),
        lambda: ssm.get_parameters(
            Names=[TENANT_SETTINGS_PARAMETER, EXCLUDED_ACCOUNTS_PARAMETER]
        ),
        lambda: ssm.get_parameters_by_path(Path=f"/loopproof/{TEST_ENVIRONMENT}"),
        lambda: ssm.get_parameter_history(Name=TENANT_SETTINGS_PARAMETER),
        lambda: ssm.describe_parameters(),
        lambda: ssm.put_parameter(
            Name=TENANT_SETTINGS_PARAMETER,
            Value="{}",
            Type="String",
            Overwrite=True,
        ),
        lambda: ssm.delete_parameter(Name=TENANT_SETTINGS_PARAMETER),
        lambda: ssm.label_parameter_version(
            Name=TENANT_SETTINGS_PARAMETER, Labels=["planted"]
        ),
        lambda: ssm.add_tags_to_resource(
            ResourceType="Parameter",
            ResourceId=TENANT_SETTINGS_PARAMETER,
            Tags=[{"Key": "planted", "Value": "yes"}],
        ),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"

    assert not probe.can_assume(outputs["outsider_role_arn"], connector["external_id"])


def test_every_setting_changed(connector, ssm_client):
    """
    With every setting changed, the parameter holds exactly those settings' bytes, updated in place. The same
    settings written another way plan no change. Last in the file: it changes the deployment.
    """
    write_tfvars(
        CONNECTOR_ROOT,
        {**connector["tfvars"], "tenant_settings": CHANGED_TENANT_SETTINGS},
    )
    log = terraform_check(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
    assert "Resources: 0 added, 1 changed, 0 destroyed." in log

    parameter = ssm_client.get_parameter(Name=TENANT_SETTINGS_PARAMETER)["Parameter"]
    assert parameter["Value"] == terraform_json(CHANGED_TENANT_SETTINGS)
    assert json.loads(parameter["Value"]) == CHANGED_TENANT_SETTINGS

    write_tfvars(
        CONNECTOR_ROOT,
        {**connector["tfvars"], "tenant_settings": CHANGED_WRITTEN_ANOTHER_WAY},
    )
    result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
    assert (
        result.returncode == 0
    ), "the same settings written another way planned a change"
    # The settings don't touch the role, so the connector registered once.
    assert len(connector["server"].requests) == 1
