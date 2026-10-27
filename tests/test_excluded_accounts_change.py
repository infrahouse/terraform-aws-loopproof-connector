"""
A list that changes, as a tenant changes it: excluding nothing, then an account, then nothing
again. Each apply updates the rule and the parameter in place. One test, so that the steps run in
order.
"""

import json
from typing import Any, Dict, List

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    EXCLUDED_ACCOUNTS_PARAMETER,
    RULE_NAME,
    connector_applied,
    connector_tfvars,
    finding_event,
    forwarded,
    forwarding_pattern_document,
    new_external_id,
    new_registration_token,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)

# The sample event's finding account, excluded in the middle step.
ACCOUNT = "444455556666"
OTHER_ACCOUNT = "999988887777"


def assert_excluded(events_client: Any, ssm_client: Any, excluded: List[str]) -> None:
    """
    Check that the rule and the parameter hold the list, and that the rule acts on it.

    :param events_client: EventBridge in the tenant's Region.
    :param ssm_client: Systems Manager in the tenant's Region.
    :param excluded: The accounts that should be excluded, sorted.
    """
    pattern = json.loads(events_client.describe_rule(Name=RULE_NAME)["EventPattern"])
    assert pattern == forwarding_pattern_document(excluded)
    # GuardDuty's findings, the sample's: the rule forwards them at any severity, Low too, unless
    # their account is excluded.
    for account_id in [ACCOUNT, OTHER_ACCOUNT]:
        for severity in ["Low", "High"]:
            assert forwarded(
                events_client, finding_event(severity, account_id=account_id)
            ) is (account_id not in excluded), (account_id, severity)
    value = ssm_client.get_parameter(Name=EXCLUDED_ACCOUNTS_PARAMETER)["Parameter"][
        "Value"
    ]
    assert json.loads(value) == excluded


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_list_change_takes_effect_on_next_apply(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    events_client,
    ssm_client,
    registration_server,
):
    """Adding an account and removing it again each take one apply, which replaces nothing."""
    tfvars: Dict[str, Any] = connector_tfvars(
        aws_region, test_role_arn, registration_server.url
    )
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(CONNECTOR_ROOT, tfvars)

    with connector_applied(
        CONNECTOR_ROOT,
        ssm_client,
        [new_external_id()],
        new_registration_token(),
        destroy_after=not keep_after,
    ):
        assert_excluded(events_client, ssm_client, [])

        for excluded in [[ACCOUNT], []]:
            write_tfvars(CONNECTOR_ROOT, {**tfvars, "excluded_accounts": excluded})
            log = terraform_check(
                CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve"
            )
            # The rule's pattern and the parameter's value.
            assert "Resources: 0 added, 2 changed, 0 destroyed." in log
            assert_excluded(events_client, ssm_client, excluded)

        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert result.returncode == 0, "the plan after the last apply isn't empty"
        # The list's changes don't touch the role, so the connector registered once.
        assert len(registration_server.requests) == 1
