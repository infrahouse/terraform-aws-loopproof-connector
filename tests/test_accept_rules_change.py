"""
Rules that change, as a tenant changes them by pull request: a rule changed, then another added, then the
first removed. Each apply touches only that rule's parameter, in place, and nothing else. One test, so
that the steps run in order.
"""

from typing import Any, Dict, List

import pytest

from tests.conftest import (
    ACCEPT_RULES_PATH,
    CONNECTOR_ROOT,
    THREAT_RULE,
    VULN_CVE_RULE,
    accept_rules_by_path,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    published_rule,
    terraform,
    terraform_check,
    terraform_json,
    write_terraform_tf,
    write_tfvars,
)

# THREAT_RULE renewed: a new review-by date and reason, as a renewal is written.
RENEWED_RULE = {
    **THREAT_RULE,
    "review_by": "2027-09-30",
    "reason": "VPN endpoints are public by design; reviewed again in March",
}


def assert_published(ssm_client: Any, rules: List[Dict[str, Any]]) -> None:
    """
    Check that the parameters under the path are exactly the rules', with their values.

    :param ssm_client: Systems Manager in the tenant's Region.
    :param rules: The rules that should be published.
    """
    assert {
        name: parameter["Value"]
        for name, parameter in accept_rules_by_path(ssm_client).items()
    } == {
        f"{ACCEPT_RULES_PATH}/{rule['id']}": terraform_json(published_rule(rule))
        for rule in rules
    }


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_rule_changes_take_effect_on_next_apply(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    ssm_client,
    registration_server,
):
    """
    Changing a rule updates its parameter in place, adding one creates its parameter, and removing one
    deletes its parameter; each takes one apply, which touches nothing else, and the plan after is empty.
    """
    tfvars: Dict[str, Any] = connector_tfvars(
        aws_region, test_role_arn, registration_server.url, accept_rules=[THREAT_RULE]
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
        assert_published(ssm_client, [THREAT_RULE])

        for rules, summary in [
            ([RENEWED_RULE], "Resources: 0 added, 1 changed, 0 destroyed."),
            (
                [RENEWED_RULE, VULN_CVE_RULE],
                "Resources: 1 added, 0 changed, 0 destroyed.",
            ),
            ([VULN_CVE_RULE], "Resources: 0 added, 0 changed, 1 destroyed."),
        ]:
            write_tfvars(CONNECTOR_ROOT, {**tfvars, "accept_rules": rules})
            log = terraform_check(
                CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve"
            )
            assert summary in log, [rule["id"] for rule in rules]
            assert_published(ssm_client, rules)

        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert result.returncode == 0, "the plan after the last apply isn't empty"
        # The rules' changes don't touch the role, so the connector registered once.
        assert len(registration_server.requests) == 1
