"""
A plain install, without excluded accounts: the resources, the outputs, the trust policy, the
connector's permissions, among them the reads of resource tags, the forwarding rule and the excluded
accounts' parameter. The tests share one deployment.
"""

import json
import re
from typing import Any, Callable, Dict, Iterator, List

import pytest
from botocore.exceptions import ClientError

from tests.conftest import (
    CONNECTOR_ACTIONS,
    CONNECTOR_ROOT,
    EXCLUDED_ACCOUNTS_PARAMETER,
    EXTERNAL_IDS_PARAMETER,
    MODULE_VERSION,
    OCSF_SEVERITY_IDS,
    REGISTRATION_TOKEN_PARAMETER,
    REPOSITORY_TAG,
    TEST_ENVIRONMENT,
    ConnectorProbe,
    allowed_actions,
    as_list,
    connector_applied,
    connector_tfvars,
    finding_event,
    inline_policy_statements,
    new_external_id,
    new_registration_token,
    policy_statements,
    registration_server_running,
    terraform_check,
    wait_for,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)

FORWARDED = ["High", "Critical", "Fatal"]
NOT_FORWARDED = ["Low", "Medium", "Informational"]
OTHER_ACCOUNT_ID = "111122223333"


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
) -> Iterator[Dict[str, Any]]:
    """Install the connector, which registers with a stand-in for LoopProof's API."""
    external_id = new_external_id()
    with registration_server_running() as server:
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(
            CONNECTOR_ROOT, connector_tfvars(aws_region, test_role_arn, server.url)
        )
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
                "external_id": external_id,
                "server": server,
                "raw_outputs": terraform_check(CONNECTOR_ROOT, "output", "-json"),
            }


def test_install(connector, iam_client, events_client, aws_region):
    """A plain install creates the role, the rule and the target, and sets the outputs."""
    outputs = connector["outputs"]
    account_id = outputs["event_bus_arn"].split(":")[4]

    assert outputs["role_name"] == f"loopproof-{TEST_ENVIRONMENT}-connector"
    assert (
        outputs["role_arn"]
        == f"arn:aws:iam::{account_id}:role/loopproof-{TEST_ENVIRONMENT}-connector"
    )
    assert outputs["event_rule_arn"] == (
        f"arn:aws:events:{aws_region}:{account_id}:rule/loopproof-{TEST_ENVIRONMENT}-findings"
    )
    # The tenant's Region, not the control plane's bus Region.
    assert outputs["region"] == aws_region
    assert outputs["excluded_accounts_parameter"] == EXCLUDED_ACCOUNTS_PARAMETER

    role = iam_client.get_role(RoleName=outputs["role_name"])["Role"]
    tags = {tag["Key"]: tag["Value"] for tag in role.get("Tags", [])}
    assert tags["module_version"] == MODULE_VERSION
    assert tags["created_by_module"] == "infrahouse/loopproof-connector/aws"
    assert tags["loopproof_environment"] == TEST_ENVIRONMENT

    rule = events_client.describe_rule(Name=f"loopproof-{TEST_ENVIRONMENT}-findings")
    assert rule["Arn"] == outputs["event_rule_arn"]
    assert rule["State"] == "ENABLED"
    assert rule["EventBusName"] == "default"
    targets = events_client.list_targets_by_rule(Rule=rule["Name"])["Targets"]
    assert [target["Arn"] for target in targets] == [outputs["event_bus_arn"]]


def test_external_id_not_exposed(connector, iam_client, events_client):
    """The ExternalId appears in no output, no tag, and nowhere in the plan or apply output."""
    external_id = connector["external_id"]
    outputs = connector["outputs"]

    assert external_id not in connector["raw_outputs"]
    assert external_id not in connector["log"]
    # The trust policy shows in the plan only masked.
    assert re.search(r"assume_role_policy\s+=\s+\(sensitive value\)", connector["log"])

    target = events_client.list_targets_by_rule(
        Rule=f"loopproof-{TEST_ENVIRONMENT}-findings"
    )["Targets"][0]
    for role_name in [outputs["role_name"], target["RoleArn"].split("/")[-1]]:
        role = iam_client.get_role(RoleName=role_name)["Role"]
        assert external_id not in json.dumps(role.get("Tags", []))
        assert external_id not in role.get("Description", "")
    rule_tags = events_client.list_tags_for_resource(
        ResourceARN=outputs["event_rule_arn"]
    )["Tags"]
    assert external_id not in json.dumps(rule_tags)


def test_trust(connector, boto3_session, aws_region, iam_client):
    """Only loopproof-<env>-* roles in the control-plane account, with a listed ExternalId, may assume the role."""
    outputs = connector["outputs"]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    right = connector["external_id"]

    wait_for(
        lambda: probe.can_assume(outputs["probe_role_arn"], right),
        "the probe role can assume the connector role with the right ExternalId",
    )
    # The right ExternalId works now, so the trust policy is in effect: these denials are real.
    assert not probe.can_assume(
        outputs["probe_role_arn"], None
    ), "assumed without an ExternalId"
    assert not probe.can_assume(
        outputs["probe_role_arn"], new_external_id()
    ), "assumed with a wrong ExternalId"
    # The outsider's own permissions allow sts:AssumeRole on the connector role, exactly like the
    # probe's, so its denial comes from the connector's trust policy.
    simulated = iam_client.simulate_principal_policy(
        PolicySourceArn=outputs["outsider_role_arn"],
        ActionNames=["sts:AssumeRole"],
        ResourceArns=[outputs["role_arn"]],
    )["EvaluationResults"][0]
    assert simulated["EvalDecision"] == "allowed", simulated
    assert not probe.can_assume(
        outputs["outsider_role_arn"], right
    ), "assumed from a role outside loopproof-<env>-*"


def test_connector_trust_policy(connector, iam_client):
    """The trust policy names the control-plane account and constrains the role name and the ExternalId."""
    outputs = connector["outputs"]
    account_id = outputs["event_bus_arn"].split(":")[4]
    role = iam_client.get_role(RoleName=outputs["role_name"])["Role"]

    statements = policy_statements(role["AssumeRolePolicyDocument"])
    assert len(statements) == 1
    statement = statements[0]
    assert statement["Effect"] == "Allow"
    assert as_list(statement["Action"]) == ["sts:AssumeRole"]
    assert as_list(statement["Principal"]["AWS"]) == [f"arn:aws:iam::{account_id}:root"]
    assert as_list(statement["Condition"]["ArnLike"]["aws:PrincipalArn"]) == [
        f"arn:aws:iam::{account_id}:role/loopproof-{TEST_ENVIRONMENT}-*"
    ]
    assert as_list(statement["Condition"]["StringEquals"]["sts:ExternalId"]) == [
        connector["external_id"]
    ]


def test_connector_permissions(connector, iam_client):
    """
    The connector role may only read findings and set their status and comment, read the excluded
    accounts, read repositories' tags and query the Config aggregators.
    """
    role_name = connector["outputs"]["role_name"]
    statements = inline_policy_statements(iam_client, role_name)

    assert sorted(iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]) == [
        "config-aggregator-query",
        "ecr-repository-tags",
        "excluded-accounts-parameter",
        "security-hub-findings",
    ]
    assert allowed_actions(iam_client, role_name) == CONNECTOR_ACTIONS
    # No wildcard actions, and every Deny only narrows BatchUpdateFindings.
    assert not [
        action
        for statement in statements
        for action in as_list(statement["Action"])
        if "*" in action
    ]
    denied = [statement for statement in statements if statement["Effect"] == "Deny"]
    assert {
        action for statement in denied for action in as_list(statement["Action"])
    } == {"securityhub:BatchUpdateFindings"}


def test_connector_excluded_accounts_policy(connector, iam_client, ssm_client):
    """The connector role's second policy allows GetParameter on the excluded accounts' parameter alone."""
    statements = policy_statements(
        iam_client.get_role_policy(
            RoleName=connector["outputs"]["role_name"],
            PolicyName="excluded-accounts-parameter",
        )["PolicyDocument"]
    )
    parameter_arn = ssm_client.get_parameter(Name=EXCLUDED_ACCOUNTS_PARAMETER)[
        "Parameter"
    ]["ARN"]

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["ssm:GetParameter"]
    assert as_list(statements[0]["Resource"]) == [parameter_arn]
    assert "Condition" not in statements[0]


@pytest.mark.parametrize(
    "action, context, decision",
    [
        ("securityhub:GetFindings", {}, "allowed"),
        # BatchUpdateFindingsV2 setting the status, the comment, or both.
        (
            "securityhub:BatchUpdateFindings",
            {"OCSFSyntaxPath/StatusId": "4"},
            "allowed",
        ),
        (
            "securityhub:BatchUpdateFindings",
            {"OCSFSyntaxPath/Comment": "Tracked in LIN-1"},
            "allowed",
        ),
        (
            "securityhub:BatchUpdateFindings",
            {"OCSFSyntaxPath/StatusId": "4", "OCSFSyntaxPath/Comment": "Fixed"},
            "allowed",
        ),
        # Changing the severity is not LoopProof's business.
        (
            "securityhub:BatchUpdateFindings",
            {"OCSFSyntaxPath/StatusId": "4", "OCSFSyntaxPath/SeverityId": "1"},
            "explicitDeny",
        ),
        # The ASFF BatchUpdateFindings API carries no OCSF fields.
        (
            "securityhub:BatchUpdateFindings",
            {"ASFFSyntaxPath/Workflow.Status": "SUPPRESSED"},
            "explicitDeny",
        ),
        ("securityhub:BatchImportFindings", {}, "implicitDeny"),
        ("securityhub:DisableSecurityHubV2", {}, "implicitDeny"),
        ("securityhub:CreateAutomationRuleV2", {}, "implicitDeny"),
        ("iam:PassRole", {}, "implicitDeny"),
        ("iam:CreateAccessKey", {}, "implicitDeny"),
        ("s3:GetObject", {}, "implicitDeny"),
        ("guardduty:GetFindings", {}, "implicitDeny"),
    ],
)
def test_connector_permissions_simulated(
    connector, iam_client, action, context, decision
):
    """The IAM policy simulator agrees with the intent of every statement."""
    result = iam_client.simulate_principal_policy(
        PolicySourceArn=connector["outputs"]["role_arn"],
        ActionNames=[action],
        ContextEntries=[
            {
                "ContextKeyName": f"securityhub:{key}",
                "ContextKeyValues": [value],
                "ContextKeyType": "string",
            }
            for key, value in context.items()
        ],
    )["EvaluationResults"][0]
    assert result["EvalDecision"] == decision, result


@pytest.mark.parametrize(
    "action, name, decision",
    [
        ("ssm:GetParameter", EXCLUDED_ACCOUNTS_PARAMETER, "allowed"),
        # LoopProof's role can't read the tenant's copies of the ExternalIds and the token.
        ("ssm:GetParameter", EXTERNAL_IDS_PARAMETER, "implicitDeny"),
        ("ssm:GetParameter", REGISTRATION_TOKEN_PARAMETER, "implicitDeny"),
        ("ssm:GetParameters", EXCLUDED_ACCOUNTS_PARAMETER, "implicitDeny"),
        ("ssm:GetParametersByPath", f"/loopproof/{TEST_ENVIRONMENT}", "implicitDeny"),
        ("ssm:GetParameterHistory", EXCLUDED_ACCOUNTS_PARAMETER, "implicitDeny"),
        ("ssm:PutParameter", EXCLUDED_ACCOUNTS_PARAMETER, "implicitDeny"),
        ("ssm:DeleteParameter", EXCLUDED_ACCOUNTS_PARAMETER, "implicitDeny"),
        ("ssm:AddTagsToResource", EXCLUDED_ACCOUNTS_PARAMETER, "implicitDeny"),
    ],
)
def test_connector_ssm_simulated(
    connector, iam_client, aws_region, action, name, decision
):
    """In SSM, the IAM policy simulator lets the connector role only read the excluded accounts' parameter."""
    account_id = connector["outputs"]["event_bus_arn"].split(":")[4]
    # A hierarchical parameter's name starts with "/", which its ARN doesn't repeat.
    resource_arn = f"arn:aws:ssm:{aws_region}:{account_id}:parameter{name}"
    result = iam_client.simulate_principal_policy(
        PolicySourceArn=connector["outputs"]["role_arn"],
        ActionNames=[action],
        ResourceArns=[resource_arn],
    )["EvaluationResults"][0]
    assert result["EvalDecision"] == decision, result


def test_connector_repository_tags_policy(connector, iam_client):
    """
    The connector role's policy ecr-repository-tags allows ListTagsForResource on the account's ECR
    repositories, in every Region, and nothing else.
    """
    account_id = connector["outputs"]["event_bus_arn"].split(":")[4]
    statements = policy_statements(
        iam_client.get_role_policy(
            RoleName=connector["outputs"]["role_name"],
            PolicyName="ecr-repository-tags",
        )["PolicyDocument"]
    )

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["ecr:ListTagsForResource"]
    assert as_list(statements[0]["Resource"]) == [
        f"arn:aws:ecr:*:{account_id}:repository/*"
    ]
    assert "Condition" not in statements[0]


@pytest.mark.parametrize(
    "action, resource, decision",
    [
        # Any repository of the account, in any Region: a finding's repository is in its own Region.
        (
            "ecr:ListTagsForResource",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "allowed",
        ),
        (
            "ecr:ListTagsForResource",
            "arn:aws:ecr:{other_region}:{account}:repository/team/app",
            "allowed",
        ),
        (
            "ecr:ListTagsForResource",
            "arn:aws:ecr:{region}:{other_account}:repository/app",
            "implicitDeny",
        ),
        # Nothing else of ECR: not the images, the repositories' settings or their tags' changes.
        (
            "ecr:DescribeRepositories",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        (
            "ecr:DescribeImages",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        (
            "ecr:BatchGetImage",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        (
            "ecr:GetRepositoryPolicy",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        (
            "ecr:TagResource",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        (
            "ecr:UntagResource",
            "arn:aws:ecr:{region}:{account}:repository/app",
            "implicitDeny",
        ),
        ("ecr:GetAuthorizationToken", "*", "implicitDeny"),
        # Nor any other resource's tags.
        ("tag:GetResources", "*", "implicitDeny"),
        # A query of any aggregator of the account in the module's Region, and only there.
        (
            "config:SelectAggregateResourceConfig",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "allowed",
        ),
        (
            "config:SelectAggregateResourceConfig",
            "arn:aws:config:{other_region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:SelectAggregateResourceConfig",
            "arn:aws:config:{region}:{other_account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        # Nothing else of AWS Config: no other read of an aggregator, of the account's own configuration
        # or of the aggregators' list, and no change to an aggregator.
        (
            "config:GetAggregateResourceConfig",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:BatchGetAggregateResourceConfig",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:ListAggregateDiscoveredResources",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:PutConfigurationAggregator",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        (
            "config:DeleteConfigurationAggregator",
            "arn:aws:config:{region}:{account}:config-aggregator/config-aggregator-abcd1234",
            "implicitDeny",
        ),
        ("config:DescribeConfigurationAggregators", "*", "implicitDeny"),
        ("config:SelectResourceConfig", "*", "implicitDeny"),
    ],
)
def test_connector_tags_simulated(
    connector, iam_client, aws_region, action, resource, decision
):
    """
    The IAM policy simulator lets the connector role read the account's repositories' tags and query the
    account's aggregators in the module's Region, and no more.
    """
    account_id = connector["outputs"]["event_bus_arn"].split(":")[4]
    other_region = "us-east-1" if aws_region != "us-east-1" else "us-west-1"
    result = iam_client.simulate_principal_policy(
        PolicySourceArn=connector["outputs"]["role_arn"],
        ActionNames=[action],
        ResourceArns=[
            resource.format(
                region=aws_region,
                other_region=other_region,
                account=account_id,
                other_account=OTHER_ACCOUNT_ID,
            )
        ],
    )["EvaluationResults"][0]
    assert result["EvalDecision"] == decision, result


def test_connector_reads_repository_tags(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof reads a repository's tags, and nothing else of ECR, nor the tags
    of other resources.
    """
    outputs = connector["outputs"]
    repository_arn = outputs["repository_arn"]
    repository_name = repository_arn.split("/", 1)[1]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    tags: List[List[Dict[str, str]]] = []

    def read() -> bool:
        try:
            ecr = probe.session(
                outputs["probe_role_arn"], connector["external_id"]
            ).client("ecr")
            tags.append(ecr.list_tags_for_resource(resourceArn=repository_arn)["tags"])
        except ClientError as err:
            # STS answers AccessDenied, ECR AccessDeniedException, until IAM has the change.
            if err.response["Error"]["Code"] in (
                "AccessDenied",
                "AccessDeniedException",
            ):
                return False
            raise
        return True

    wait_for(read, "the connector role can read the repository's tags")
    assert REPOSITORY_TAG in tags[-1]

    session = probe.session(outputs["probe_role_arn"], connector["external_id"])
    ecr = session.client("ecr")
    tagging = session.client("resourcegroupstaggingapi")
    refused: List[Callable[[], Any]] = [
        lambda: ecr.describe_repositories(repositoryNames=[repository_name]),
        lambda: ecr.describe_images(repositoryName=repository_name),
        lambda: ecr.get_authorization_token(),
        lambda: ecr.tag_resource(
            resourceArn=repository_arn, tags=[{"Key": "added", "Value": "by-loopproof"}]
        ),
        lambda: tagging.get_resources(),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"


def test_connector_aggregator_policy(connector, iam_client, aws_region):
    """
    The connector role's policy config-aggregator-query allows SelectAggregateResourceConfig on every
    aggregator of the account in the module's Region, and nothing else.
    """
    account_id = connector["outputs"]["event_bus_arn"].split(":")[4]
    statements = policy_statements(
        iam_client.get_role_policy(
            RoleName=connector["outputs"]["role_name"],
            PolicyName="config-aggregator-query",
        )["PolicyDocument"]
    )

    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["config:SelectAggregateResourceConfig"]
    assert as_list(statements[0]["Resource"]) == [
        f"arn:aws:config:{aws_region}:{account_id}:config-aggregator/*"
    ]
    assert "Condition" not in statements[0]


def test_connector_queries_aggregator(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof queries an aggregator by its name, as it queries Control Tower's,
    without having to find it, and can't list the aggregators or query the account's own configuration.
    """
    outputs = connector["outputs"]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    query = (
        "SELECT accountId, awsRegion, resourceId, tags"
        " WHERE resourceType = 'AWS::ECR::Repository'"
    )
    answers: List[Dict[str, Any]] = []

    def select() -> bool:
        try:
            config = probe.session(
                outputs["probe_role_arn"], connector["external_id"]
            ).client("config")
            answers.append(
                config.select_aggregate_resource_config(
                    Expression=query,
                    ConfigurationAggregatorName=outputs["aggregator_name"],
                )
            )
        except ClientError as err:
            # STS answers AccessDenied, AWS Config AccessDeniedException, until IAM has the change.
            if err.response["Error"]["Code"] in (
                "AccessDenied",
                "AccessDeniedException",
            ):
                return False
            raise
        return True

    wait_for(select, "the connector role can query the aggregator")
    assert isinstance(answers[-1]["Results"], list)

    config = probe.session(outputs["probe_role_arn"], connector["external_id"]).client(
        "config"
    )
    refused: List[Callable[[], Any]] = [
        lambda: config.describe_configuration_aggregators(),
        lambda: config.select_resource_config(Expression=query),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"


def test_excluded_accounts_parameter(connector, ssm_client):
    """
    With no account excluded, the parameter still exists and holds an empty JSON list, as a standard
    String parameter, which isn't encrypted with a KMS key.
    """
    parameter = ssm_client.get_parameter(Name=EXCLUDED_ACCOUNTS_PARAMETER)["Parameter"]
    assert parameter["Type"] == "String"
    assert parameter["Value"] == "[]"

    described = ssm_client.describe_parameters(
        ParameterFilters=[
            {"Key": "Name", "Option": "Equals", "Values": [EXCLUDED_ACCOUNTS_PARAMETER]}
        ]
    )["Parameters"]
    assert len(described) == 1
    assert described[0]["Tier"] == "Standard"
    assert "KeyId" not in described[0]

    tags = {
        tag["Key"]: tag["Value"]
        for tag in ssm_client.list_tags_for_resource(
            ResourceType="Parameter", ResourceId=EXCLUDED_ACCOUNTS_PARAMETER
        )["TagList"]
    }
    assert tags["created_by_module"] == "infrahouse/loopproof-connector/aws"
    assert tags["loopproof_environment"] == TEST_ENVIRONMENT


def test_connector_reads_excluded_accounts(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof reads the parameter, with no KMS permission, and nothing else
    in SSM.
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
                ssm.get_parameter(Name=EXCLUDED_ACCOUNTS_PARAMETER)["Parameter"][
                    "Value"
                ]
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

    wait_for(read, "the connector role can read the excluded accounts")
    assert values[-1] == "[]"

    ssm = probe.session(outputs["probe_role_arn"], connector["external_id"]).client(
        "ssm"
    )
    refused: List[Callable[[], Any]] = [
        lambda: ssm.get_parameter(Name=EXTERNAL_IDS_PARAMETER, WithDecryption=True),
        lambda: ssm.get_parameter(
            Name=REGISTRATION_TOKEN_PARAMETER, WithDecryption=True
        ),
        lambda: ssm.get_parameters(Names=[EXCLUDED_ACCOUNTS_PARAMETER]),
        lambda: ssm.get_parameters_by_path(Path=f"/loopproof/{TEST_ENVIRONMENT}"),
        lambda: ssm.get_parameter_history(Name=EXCLUDED_ACCOUNTS_PARAMETER),
        lambda: ssm.describe_parameters(),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"


@pytest.mark.parametrize("severity", FORWARDED + NOT_FORWARDED)
def test_forwarding_pattern(connector, events_client, severity):
    """By default, High, Critical and Fatal findings are forwarded; Low, Medium and Informational aren't."""
    pattern = events_client.describe_rule(
        Name=f"loopproof-{TEST_ENVIRONMENT}-findings"
    )["EventPattern"]
    matched = events_client.test_event_pattern(
        EventPattern=pattern, Event=json.dumps(finding_event(severity))
    )
    assert matched["Result"] is (severity in FORWARDED)


@pytest.mark.parametrize("activity", ["Create", "Update", "Close"])
def test_forwarding_pattern_activities(connector, events_client, activity):
    """New, updated and closed High findings all pass; the control plane drops its own echoes."""
    pattern = events_client.describe_rule(
        Name=f"loopproof-{TEST_ENVIRONMENT}-findings"
    )["EventPattern"]
    matched = events_client.test_event_pattern(
        EventPattern=pattern, Event=json.dumps(finding_event("High", activity))
    )
    assert matched["Result"] is True


def test_forwarding_pattern_ignores_cspm_events(connector, events_client):
    """Security Hub CSPM events share the source but not the detail-type, and don't match."""
    pattern = events_client.describe_rule(
        Name=f"loopproof-{TEST_ENVIRONMENT}-findings"
    )["EventPattern"]
    event = finding_event("Critical")
    event["detail-type"] = "Security Hub Findings - Imported"
    matched = events_client.test_event_pattern(
        EventPattern=pattern, Event=json.dumps(event)
    )
    assert matched["Result"] is False


def test_forwarding_pattern_document(connector, events_client):
    """
    The rule matches the Findings Imported V2 events by OCSF severity_id. With no account excluded,
    the pattern has no account filter: it's the pattern of 0.2.0, so upgrading changes no rule.
    """
    pattern = json.loads(
        events_client.describe_rule(Name=f"loopproof-{TEST_ENVIRONMENT}-findings")[
            "EventPattern"
        ]
    )
    assert pattern == {
        "source": ["aws.securityhub"],
        "detail-type": ["Findings Imported V2"],
        "detail": {
            "findings": {
                "severity_id": [OCSF_SEVERITY_IDS[severity] for severity in FORWARDED]
            }
        },
    }


def test_forwarding_target(connector, events_client, iam_client):
    """The target is the control-plane bus, through a role that may only put events on it."""
    outputs = connector["outputs"]
    bus_arn = outputs["event_bus_arn"]
    targets = events_client.list_targets_by_rule(
        Rule=f"loopproof-{TEST_ENVIRONMENT}-findings"
    )["Targets"]
    assert len(targets) == 1
    assert targets[0]["Arn"] == bus_arn
    role_name = targets[0]["RoleArn"].split("/")[-1]
    assert role_name == f"loopproof-{TEST_ENVIRONMENT}-forwarder"

    assert (
        iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        == []
    )
    policy_names = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert len(policy_names) == 1
    statements = policy_statements(
        iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_names[0])[
            "PolicyDocument"
        ]
    )
    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert as_list(statements[0]["Action"]) == ["events:PutEvents"]
    assert as_list(statements[0]["Resource"]) == [bus_arn]
    assert "Condition" not in statements[0]

    trust = policy_statements(
        iam_client.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    )
    assert len(trust) == 1
    assert as_list(trust[0]["Principal"]["Service"]) == ["events.amazonaws.com"]
    assert as_list(trust[0]["Condition"]["ArnEquals"]["aws:SourceArn"]) == [
        outputs["event_rule_arn"]
    ]
