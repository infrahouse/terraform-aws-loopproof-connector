"""
A plain install, without a registration token: the resources, the outputs, the trust policy,
the connector's permissions and the forwarding rule. The tests share one deployment.
"""

import json
import re
from typing import Any, Dict, Iterator

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    MODULE_VERSION,
    OCSF_SEVERITY_IDS,
    TEST_ENVIRONMENT,
    ConnectorProbe,
    as_list,
    connector_applied,
    connector_tfvars,
    finding_event,
    new_external_id,
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


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after
) -> Iterator[Dict[str, Any]]:
    """Install the connector without a registration token, with a registration server listening."""
    external_id = new_external_id()
    with registration_server_running() as server:
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(
            CONNECTOR_ROOT,
            connector_tfvars(aws_region, test_role_arn, [external_id], server.url),
        )
        with connector_applied(CONNECTOR_ROOT, destroy_after=not keep_after) as (
            outputs,
            log,
        ):
            yield {
                "outputs": outputs,
                "log": log,
                "external_id": external_id,
                "server": server,
                "raw_outputs": terraform_check(CONNECTOR_ROOT, "output", "-json"),
            }


@pytest.fixture()
def events_client(boto3_session, aws_region):
    return boto3_session.client("events", region_name=aws_region)


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
    # Terraform leaves null outputs out of `terraform output -json`.
    assert outputs.get("registered") is None

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


def test_no_token_makes_no_request(connector):
    """Without a registration token, the module doesn't call LoopProof."""
    assert connector["server"].requests == []
    assert connector["outputs"].get("registered") is None


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
    """The connector role may only read findings and set their status and comment."""
    role_name = connector["outputs"]["role_name"]

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
    allowed = [statement for statement in statements if statement["Effect"] == "Allow"]
    assert {
        action for statement in allowed for action in as_list(statement["Action"])
    } == {
        "securityhub:GetFindings",
        "securityhub:BatchUpdateFindings",
    }
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
    """The rule matches the Findings Imported V2 events by OCSF severity_id."""
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
