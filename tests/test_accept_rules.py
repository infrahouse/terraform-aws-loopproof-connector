"""
An install with accept rules, one of each shape and one as long as a Standard parameter holds: the module
publishes each rule as its own SSM parameter under /loopproof/<environment>/accept-rules, and the connector
role reads them by path, as LoopProof will, and nothing else new. The tests share one deployment and don't
change it; test_accept_rules_change.py changes the rules.
"""

import json
import re
from typing import Any, Callable, Dict, Iterator, List

import pytest
from botocore.exceptions import ClientError

from tests.conftest import (
    ACCEPT_RULES_PATH,
    CONNECTOR_ROOT,
    EXCEPTION_RULE,
    EXCLUDED_ACCOUNTS_PARAMETER,
    EXTERNAL_IDS_PARAMETER,
    STANDARD_PARAMETER_LIMIT,
    TEST_ENVIRONMENT,
    THREAT_RULE,
    VULN_CVE_RULE,
    VULN_PACKAGE_RULE,
    ConnectorProbe,
    accept_rules_by_path,
    as_list,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    policy_statements,
    published_rule,
    registration_server_running,
    rule_of_length,
    ssm_length,
    terraform,
    terraform_json,
    wait_for,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)

# As long as a Standard parameter holds, as SSM counts: the q's combining acute counts on its own, and
# the emoji twice. The plan's check counts the same way, so it neither refuses this rule nor lets a longer
# one reach SSM.
FULL_RULE = rule_of_length(STANDARD_PARAMETER_LIMIT, tail="q\u0301\U0001f600")
RULES = [THREAT_RULE, VULN_CVE_RULE, VULN_PACKAGE_RULE, EXCEPTION_RULE, FULL_RULE]


def parameter_name(rule: Dict[str, Any]) -> str:
    """
    :param rule: An accept rule.
    :return: The name of the parameter that publishes it.
    """
    return f"{ACCEPT_RULES_PATH}/{rule['id']}"


def reversed_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    :param rule: An accept rule.
    :return: The same rule written another way: its fields, and its where's, in reverse order, and every
        list reversed.
    """

    def reverse(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: reverse(value[key]) for key in reversed(list(value))}
        if isinstance(value, list):
            return [reverse(item) for item in reversed(value)]
        return value

    return reverse(rule)


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
) -> Iterator[Dict[str, Any]]:
    """Install the connector with an accept rule of each shape."""
    external_id = new_external_id()
    with registration_server_running() as server:
        tfvars = connector_tfvars(
            aws_region, test_role_arn, server.url, accept_rules=RULES
        )
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
            }


def test_one_parameter_per_rule(connector, ssm_client):
    """
    Each rule is a standard String parameter, named by its id under the path the output names, holding
    the rule as JSON: its fields sorted by name, its lists sorted, and the same bytes every time.
    """
    assert connector["outputs"]["accept_rules_parameter_path"] == ACCEPT_RULES_PATH
    parameters = accept_rules_by_path(ssm_client)

    assert sorted(parameters) == sorted(parameter_name(rule) for rule in RULES)
    for rule in RULES:
        parameter = parameters[parameter_name(rule)]
        assert parameter["Type"] == "String"
        assert parameter["Value"] == terraform_json(published_rule(rule)), rule["id"]
    assert (
        ssm_length(parameters[parameter_name(FULL_RULE)]["Value"])
        == STANDARD_PARAMETER_LIMIT
    )

    described = ssm_client.describe_parameters(
        ParameterFilters=[{"Key": "Path", "Values": [ACCEPT_RULES_PATH]}]
    )["Parameters"]
    assert len(described) == len(RULES)
    for parameter in described:
        assert parameter["Tier"] == "Standard"
        assert "KeyId" not in parameter


def test_unset_fields_left_out(connector, ssm_client):
    """
    A rule's value holds the fields it sets and no others: no other kind's, no empty selector, and
    behavioral_exception only where it is true.
    """
    values = {
        name: json.loads(parameter["Value"])
        for name, parameter in accept_rules_by_path(ssm_client).items()
    }
    threat = values[parameter_name(THREAT_RULE)]
    assert sorted(threat) == [
        "decision_ref",
        "finding_types",
        "id",
        "kind",
        "reason",
        "review_by",
        "where",
    ]
    assert sorted(threat["where"]) == ["accounts", "tags"]
    assert sorted(values[parameter_name(VULN_CVE_RULE)]["where"]) == [
        "image_repositories"
    ]
    assert "cves" not in values[parameter_name(VULN_PACKAGE_RULE)]
    assert values[parameter_name(EXCEPTION_RULE)]["behavioral_exception"] is True


def test_parameter_tags(connector, ssm_client):
    """The parameters carry the module's tags, as the excluded accounts' does."""
    for rule in RULES:
        tags = {
            tag["Key"]: tag["Value"]
            for tag in ssm_client.list_tags_for_resource(
                ResourceType="Parameter", ResourceId=parameter_name(rule)
            )["TagList"]
        }
        assert tags["created_by_module"] == "infrahouse/loopproof-connector/aws"
        assert tags["loopproof_environment"] == TEST_ENVIRONMENT


def test_plan_shows_rules(connector):
    """The plan shows each rule it publishes: a rule is no secret, and a reviewer should see it."""
    for rule in RULES:
        published = re.search(
            r'name\s+=\s+"' + re.escape(parameter_name(rule)) + '"', connector["log"]
        )
        assert published, f"the plan doesn't show {parameter_name(rule)}"
        assert rule["reason"] in connector["log"]
        assert rule["decision_ref"] in connector["log"]


def test_rules_written_another_way_change_nothing(connector):
    """
    The same rules in another order, with their fields and their lists in another order, plan no change:
    the module publishes the same bytes for the same rule.
    """
    write_tfvars(
        CONNECTOR_ROOT,
        {
            **connector["tfvars"],
            "accept_rules": [reversed_rule(rule) for rule in reversed(RULES)],
        },
    )
    try:
        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert (
            result.returncode == 0
        ), "the same rules written another way planned a change"
    finally:
        write_tfvars(CONNECTOR_ROOT, connector["tfvars"])


def test_accept_rules_policy(connector, iam_client, aws_region):
    """
    The connector role's policy accept-rules-parameters allows GetParametersByPath on the path, and
    GetParameter and GetParameters on the parameters under it, and nothing else.
    """
    account_id = connector["outputs"]["event_bus_arn"].split(":")[4]
    path_arn = f"arn:aws:ssm:{aws_region}:{account_id}:parameter{ACCEPT_RULES_PATH}"
    statements = policy_statements(
        iam_client.get_role_policy(
            RoleName=connector["outputs"]["role_name"],
            PolicyName="accept-rules-parameters",
        )["PolicyDocument"]
    )

    assert sorted(
        (
            statement["Effect"],
            sorted(as_list(statement["Action"])),
            as_list(statement["Resource"]),
        )
        for statement in statements
    ) == [
        ("Allow", ["ssm:GetParameter", "ssm:GetParameters"], [f"{path_arn}/*"]),
        ("Allow", ["ssm:GetParametersByPath"], [path_arn]),
    ]
    assert not [statement for statement in statements if "Condition" in statement]


def test_connector_reads_rules_by_path(connector, boto3_session, aws_region):
    """
    As the connector role, LoopProof reads every rule by path, with no KMS permission, and each by
    name; it can't write them, or read anything else new.
    """
    outputs = connector["outputs"]
    probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
    read: List[Dict[str, Dict[str, Any]]] = []

    def read_by_path() -> bool:
        try:
            read.append(
                accept_rules_by_path(
                    probe.session(
                        outputs["probe_role_arn"], connector["external_id"]
                    ).client("ssm")
                )
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

    wait_for(read_by_path, "the connector role can read the accept rules by path")
    assert {name: parameter["Value"] for name, parameter in read[-1].items()} == {
        parameter_name(rule): terraform_json(published_rule(rule)) for rule in RULES
    }

    ssm = probe.session(outputs["probe_role_arn"], connector["external_id"]).client(
        "ssm"
    )
    names = [parameter_name(rule) for rule in RULES]
    assert ssm.get_parameter(Name=names[0])["Parameter"]["Value"] == terraform_json(
        published_rule(RULES[0])
    )
    assert sorted(
        parameter["Name"] for parameter in ssm.get_parameters(Names=names)["Parameters"]
    ) == sorted(names)

    refused: List[Callable[[], Any]] = [
        lambda: ssm.get_parameters_by_path(Path=f"/loopproof/{TEST_ENVIRONMENT}"),
        lambda: ssm.get_parameters_by_path(Path="/loopproof"),
        lambda: ssm.get_parameters(Names=[EXCLUDED_ACCOUNTS_PARAMETER]),
        lambda: ssm.get_parameter(Name=EXTERNAL_IDS_PARAMETER, WithDecryption=True),
        lambda: ssm.get_parameter_history(Name=names[0]),
        lambda: ssm.describe_parameters(),
        lambda: ssm.put_parameter(
            Name=names[0], Value="{}", Type="String", Overwrite=True
        ),
        lambda: ssm.put_parameter(
            Name=f"{ACCEPT_RULES_PATH}/planted", Value="{}", Type="String"
        ),
        lambda: ssm.delete_parameter(Name=names[0]),
        lambda: ssm.label_parameter_version(Name=names[0], Labels=["planted"]),
        lambda: ssm.add_tags_to_resource(
            ResourceType="Parameter",
            ResourceId=names[0],
            Tags=[{"Key": "planted", "Value": "yes"}],
        ),
    ]
    for call in refused:
        with pytest.raises(ClientError) as err:
            call()
        assert err.value.response["Error"]["Code"] == "AccessDeniedException"
