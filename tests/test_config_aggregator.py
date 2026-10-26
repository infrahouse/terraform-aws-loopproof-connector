"""
The aggregator query, for a tenant with AWS Control Tower: with the input on, the module looks up
Control Tower's AWS Config aggregator by its name and lets the connector role query that aggregator
alone. The fixture creates a stand-in aggregator of that name outside Terraform, before the install, as
Control Tower creates the real one in the Audit account. The tests share one deployment.
"""

from typing import Any, Callable, Dict, Iterator, List

import pytest
from botocore.exceptions import ClientError

from tests.conftest import (
    CONNECTOR_ACTIONS,
    CONNECTOR_ROOT,
    CONTROL_TOWER_AGGREGATOR,
    ConnectorProbe,
    allowed_actions,
    as_list,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    policy_statements,
    registration_server_running,
    terraform,
    wait_for,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)

AGGREGATOR_POLICY = "control-tower-aggregator-query"
# What LoopProof's lookup asks: the tags of the organization's repositories.
QUERY = "SELECT accountId, awsRegion, resourceId, tags WHERE resourceType = 'AWS::ECR::Repository'"


@pytest.fixture(scope="module")
def control_tower_aggregator(boto3_session, aws_region, keep_after) -> Iterator[str]:
    """
    A stand-in for Control Tower's aggregator, in the tenant's Region, over the test account alone.

    :return: Its ARN, which ends in an ID that AWS Config generates.
    """
    config = boto3_session.client("config", region_name=aws_region)
    account_id = boto3_session.client("sts").get_caller_identity()["Account"]
    aggregator = config.put_configuration_aggregator(
        ConfigurationAggregatorName=CONTROL_TOWER_AGGREGATOR,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AwsRegions": [aws_region]}
        ],
    )["ConfigurationAggregator"]
    try:
        yield aggregator["ConfigurationAggregatorArn"]
    finally:
        if not keep_after:
            config.delete_configuration_aggregator(
                ConfigurationAggregatorName=CONTROL_TOWER_AGGREGATOR
            )


@pytest.fixture(scope="module")
def connector(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    boto3_session,
    control_tower_aggregator,
) -> Iterator[Dict[str, Any]]:
    """Install the connector with the aggregator query on, after the aggregator exists."""
    external_id = new_external_id()
    with registration_server_running() as server:
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(
            CONNECTOR_ROOT,
            connector_tfvars(
                aws_region,
                test_role_arn,
                server.url,
                enable_control_tower_aggregator_query=True,
            ),
        )
        with connector_applied(
            CONNECTOR_ROOT,
            boto3_session.client("ssm", region_name=aws_region),
            [external_id],
            new_registration_token(),
            destroy_after=not keep_after,
        ) as (outputs, _):
            yield {
                "outputs": outputs,
                "external_id": external_id,
                "aggregator_arn": control_tower_aggregator,
            }


def test_aggregator_policy(connector, iam_client):
    """
    A fourth policy allows SelectAggregateResourceConfig on the aggregator's ARN, which the module
    looked up, and nothing else; the role's other permissions are as without the input.
    """
    role_name = connector["outputs"]["role_name"]

    assert sorted(iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]) == [
        AGGREGATOR_POLICY,
        "ecr-repository-tags",
        "excluded-accounts-parameter",
        "security-hub-findings",
    ]
    assert allowed_actions(iam_client, role_name) == CONNECTOR_ACTIONS | {
        "config:SelectAggregateResourceConfig"
    }

    statements = policy_statements(
        iam_client.get_role_policy(RoleName=role_name, PolicyName=AGGREGATOR_POLICY)[
            "PolicyDocument"
        ]
    )
    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["config:SelectAggregateResourceConfig"]
    assert as_list(statements[0]["Resource"]) == [connector["aggregator_arn"]]
    assert "Condition" not in statements[0]


@pytest.mark.parametrize(
    "action, resource, decision",
    [
        ("config:SelectAggregateResourceConfig", "{aggregator}", "allowed"),
        # Another aggregator of the same account and Region, or one of the same ID elsewhere.
        (
            "config:SelectAggregateResourceConfig",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:SelectAggregateResourceConfig",
            "arn:aws:config:{other_region}:{account}:config-aggregator/{aggregator_id}",
            "implicitDeny",
        ),
        # Nothing else of AWS Config: no other read of the aggregator, of this account's own
        # configuration, or of the aggregators' list, and no change to the aggregator.
        ("config:GetAggregateResourceConfig", "{aggregator}", "implicitDeny"),
        ("config:BatchGetAggregateResourceConfig", "{aggregator}", "implicitDeny"),
        ("config:ListAggregateDiscoveredResources", "{aggregator}", "implicitDeny"),
        ("config:PutConfigurationAggregator", "{aggregator}", "implicitDeny"),
        ("config:DeleteConfigurationAggregator", "{aggregator}", "implicitDeny"),
        ("config:DescribeConfigurationAggregators", "*", "implicitDeny"),
        ("config:SelectResourceConfig", "*", "implicitDeny"),
    ],
)
def test_aggregator_simulated(
    connector, iam_client, aws_region, action, resource, decision
):
    """The IAM policy simulator lets the connector role query the aggregator it was given, and no more."""
    aggregator_arn = connector["aggregator_arn"]
    other_region = "us-east-1" if aws_region != "us-east-1" else "us-west-1"
    result = iam_client.simulate_principal_policy(
        PolicySourceArn=connector["outputs"]["role_arn"],
        ActionNames=[action],
        ResourceArns=[
            resource.format(
                aggregator=aggregator_arn,
                aggregator_id=aggregator_arn.split("/")[-1],
                region=aws_region,
                other_region=other_region,
                account=aggregator_arn.split(":")[4],
            )
        ],
    )["EvaluationResults"][0]
    assert result["EvalDecision"] == decision, result


def test_connector_queries_aggregator(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof queries the aggregator by its name, without having to find it,
    and can't list the aggregators or query this account's own configuration.
    """
    outputs = connector["outputs"]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    answers: List[Dict[str, Any]] = []

    def query() -> bool:
        try:
            config = probe.session(
                outputs["probe_role_arn"], connector["external_id"]
            ).client("config")
            answers.append(
                config.select_aggregate_resource_config(
                    Expression=QUERY,
                    ConfigurationAggregatorName=CONTROL_TOWER_AGGREGATOR,
                )
            )
        except ClientError as err:
            # Until IAM has the changes, STS answers AccessDenied, or InvalidClientTokenId for the new probe
            # role's credentials, and AWS Config AccessDeniedException.
            if err.response["Error"]["Code"] in (
                "AccessDenied",
                "InvalidClientTokenId",
                "AccessDeniedException",
            ):
                return False
            raise
        return True

    wait_for(query, "the connector role can query the aggregator")
    assert isinstance(answers[-1]["Results"], list)

    config = probe.session(outputs["probe_role_arn"], connector["external_id"]).client(
        "config"
    )
    refused: List[Callable[[], Any]] = [
        lambda: config.describe_configuration_aggregators(),
        lambda: config.select_resource_config(Expression=QUERY),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"


def test_no_change_after_install(connector):
    """The lookup reads the same ARN on the next plan, which changes nothing."""
    result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
    assert result.returncode == 0, result.stdout + result.stderr
