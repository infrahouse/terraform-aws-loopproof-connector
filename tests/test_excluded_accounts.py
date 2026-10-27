"""
An install that excludes accounts: the forwarding rule drops their findings, and the SSM parameter
publishes the sorted list for LoopProof. The tests share one deployment and don't change it;
test_excluded_accounts_change.py changes the list.
"""

import json
import re
from typing import Any, Dict, Iterator

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    DEFAULT_SEVERITIES,
    EXCLUDED_ACCOUNTS_PARAMETER,
    GUARDDUTY,
    OCSF_SEVERITY_IDS,
    RULE_NAME,
    SEVERITY_FILTERED_PRODUCTS,
    connector_applied,
    connector_tfvars,
    finding_event,
    forwarded,
    forwarding_pattern_document,
    new_external_id,
    new_registration_token,
    registration_server_running,
    terraform,
    write_terraform_tf,
    write_tfvars,
)

pytestmark = pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)

# Out of order on purpose: the module sorts the list.
EXCLUDED = ["999988887777", "111100002222"]
# The sample event's finding account.
INCLUDED = "444455556666"


@pytest.fixture(scope="module")
def connector(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
) -> Iterator[Dict[str, Any]]:
    """Install the connector excluding two accounts."""
    with registration_server_running() as server:
        tfvars = connector_tfvars(
            aws_region, test_role_arn, server.url, excluded_accounts=EXCLUDED
        )
        write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
        write_tfvars(CONNECTOR_ROOT, tfvars)
        with connector_applied(
            CONNECTOR_ROOT,
            boto3_session.client("ssm", region_name=aws_region),
            [new_external_id()],
            new_registration_token(),
            destroy_after=not keep_after,
        ) as (outputs, log):
            yield {"outputs": outputs, "log": log, "tfvars": tfvars}


def test_pattern_document(connector, events_client):
    """The rule adds anything-but on the finding's cloud.account.uid, with the sorted list."""
    pattern = json.loads(events_client.describe_rule(Name=RULE_NAME)["EventPattern"])
    assert pattern == forwarding_pattern_document(sorted(EXCLUDED))


@pytest.mark.parametrize("account_id", EXCLUDED)
@pytest.mark.parametrize("severity", list(OCSF_SEVERITY_IDS))
@pytest.mark.parametrize("product", [GUARDDUTY] + SEVERITY_FILTERED_PRODUCTS)
def test_excluded_account_dropped(
    connector, events_client, account_id, severity, product
):
    """A finding of an excluded account isn't forwarded, whatever its product and severity: GuardDuty's neither."""
    assert not forwarded(
        events_client,
        finding_event(severity, account_id=account_id, product=product),
    )


@pytest.mark.parametrize("activity", ["Create", "Update", "Close"])
def test_other_account_forwarded(connector, events_client, activity):
    """A finding of any other account is forwarded as before."""
    assert forwarded(events_client, finding_event("High", activity, INCLUDED))


@pytest.mark.parametrize("severity", list(OCSF_SEVERITY_IDS))
def test_other_account_guardduty_forwarded(connector, events_client, severity):
    """Another account's GuardDuty findings are forwarded at every severity."""
    assert forwarded(
        events_client,
        finding_event(severity, account_id=INCLUDED, product=GUARDDUTY),
    )


@pytest.mark.parametrize("severity", list(OCSF_SEVERITY_IDS))
@pytest.mark.parametrize("product", SEVERITY_FILTERED_PRODUCTS)
def test_other_account_by_severity(connector, events_client, product, severity):
    """The severity filter still applies to the other products' findings of the accounts that aren't excluded."""
    assert forwarded(
        events_client, finding_event(severity, account_id=INCLUDED, product=product)
    ) is (severity in DEFAULT_SEVERITIES)


@pytest.mark.parametrize("severity", ["Low", "High"])
def test_finding_without_account_dropped(connector, events_client, severity):
    """
    While accounts are excluded, a finding without cloud.account.uid doesn't match anything-but,
    so it isn't forwarded, GuardDuty's at any severity neither. Security Hub's findings carry it;
    the case only pins the behavior.
    """
    event = finding_event(severity, product=GUARDDUTY)
    del event["detail"]["findings"][0]["cloud"]["account"]
    assert not forwarded(events_client, event)


def test_parameter_value(connector, ssm_client):
    """The parameter holds the sorted list as JSON."""
    parameter = ssm_client.get_parameter(Name=EXCLUDED_ACCOUNTS_PARAMETER)["Parameter"]
    assert parameter["Type"] == "String"
    assert parameter["Value"] == json.dumps(sorted(EXCLUDED), separators=(",", ":"))
    assert connector["outputs"]["excluded_accounts_parameter"] == (
        EXCLUDED_ACCOUNTS_PARAMETER
    )


def test_plan_shows_list(connector):
    """The plan shows the list it publishes: account IDs aren't secret, and a reviewer should see them."""
    published = re.search(
        r"insecure_value\s+=\s+jsonencode\(([^)]*)\)", connector["log"]
    )
    assert published, "the plan doesn't show the parameter's value"
    assert re.findall(r"[0-9]{12}", published.group(1)) == sorted(EXCLUDED)


def test_reordered_list_changes_nothing(connector):
    """The module sorts the list, so the same accounts in another order plan no change."""
    write_tfvars(
        CONNECTOR_ROOT,
        {**connector["tfvars"], "excluded_accounts": list(reversed(EXCLUDED))},
    )
    result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
    assert result.returncode == 0, "reordering the list planned a change"
