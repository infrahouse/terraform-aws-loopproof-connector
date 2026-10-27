"""
The forwarding pattern as the module renders it, judged by EventBridge's TestEventPattern for every product,
severity and account, with severities at the default and widened, and excluded_accounts empty and set. The
installs check the default severities on the rule as EventBridge stores it; these cases plan the rule alone,
so they cover inputs no install uses and create nothing.
"""

import json
import logging
import subprocess
from typing import Any, Dict, List, Optional

import pytest

from tests.conftest import (
    DEFAULT_SEVERITIES,
    GUARDDUTY,
    OCSF_SEVERITY_IDS,
    RULE_ADDRESS,
    SEVERITY_FILTERED_PRODUCTS,
    TEST_ENVIRONMENT,
    VALIDATION_ROOT,
    finding_event,
    forwarding_pattern_document,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)

LOG = logging.getLogger(__name__)

CONTROL_PLANE_ACCOUNT_ID = "123456789012"
# The sample event's finding account.
INCLUDED = "444455556666"
# Sorted, as the module sorts them.
EXCLUDED = ["111100002222", "999988887777"]
WIDENED = ["Medium", "High", "Critical", "Fatal"]
CASES = [
    ("default", None, []),
    ("default-excluded", None, EXCLUDED),
    ("widened", WIDENED, []),
    ("widened-excluded", WIDENED, EXCLUDED),
]


@pytest.fixture(scope="module")
def pattern_root(aws_provider_version) -> str:
    """The validation root module, which passes every input to the module, initialized once."""
    write_terraform_tf(VALIDATION_ROOT, aws_provider_version)
    terraform_check(VALIDATION_ROOT, "init", "-input=false")
    return VALIDATION_ROOT


def rendered_rule(
    root: str,
    aws_region: str,
    test_role_arn: Optional[str],
    severities: Optional[List[str]],
    excluded_accounts: List[str],
) -> Dict[str, Any]:
    """
    Plan the forwarding rule alone, with ``-target``, and read what the plan would write.

    The parameters' ARNs are well-formed but name nothing: ``-target`` plans the rule and what it depends on,
    and the rule depends on neither parameter. If it ever does, the plan fails here, reading them.

    :param root: The validation root module.
    :param aws_region: Region for the AWS provider.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param severities: The ``severities`` input; the module's default when ``None``.
    :param excluded_accounts: The ``excluded_accounts`` input.
    :return: The rule's planned attributes.
    """
    parameter_arn = f"arn:aws:ssm:{aws_region}:{CONTROL_PLANE_ACCOUNT_ID}:parameter/loopproof/pytest-pattern"
    write_tfvars(
        root,
        {
            "region": aws_region,
            "role_arn": test_role_arn,
            "environment": TEST_ENVIRONMENT,
            "control_plane_account_id": CONTROL_PLANE_ACCOUNT_ID,
            "external_ids_parameter_arn": f"{parameter_arn}/external-ids",
            "registration_token_parameter_arn": f"{parameter_arn}/registration-token",
            "event_bus_arn": (
                f"arn:aws:events:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:event-bus/loopproof-pytest-findings"
            ),
            "registration_url": "https://api.staging.loopproof.ai/connector/registrations",
            "severities": severities,
            "excluded_accounts": excluded_accounts,
        },
    )
    terraform_check(
        root, "plan", "-input=false", f"-target={RULE_ADDRESS}", "-out=tfplan"
    )
    result = subprocess.run(
        ["terraform", "show", "-json", "tfplan"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    rules = [
        resource["change"]["after"]
        for resource in json.loads(result.stdout)["resource_changes"]
        if resource["address"] == RULE_ADDRESS
    ]
    assert len(rules) == 1, f"the plan holds {len(rules)} of {RULE_ADDRESS}"
    return rules[0]


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "severities, excluded_accounts",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_rendered_pattern(
    pattern_root,
    aws_region,
    test_role_arn,
    events_client,
    severities,
    excluded_accounts,
):
    """
    A GuardDuty finding is forwarded at every severity, and Inspector's, CSPM's and exposure findings only at a
    severity in severities; an excluded account's finding never is, GuardDuty's neither.
    """
    rule = rendered_rule(
        pattern_root, aws_region, test_role_arn, severities, excluded_accounts
    )
    assert json.loads(rule["event_pattern"]) == forwarding_pattern_document(
        excluded_accounts, severities
    )

    forwarded_severities = severities or DEFAULT_SEVERITIES
    mismatches = []
    for product in [GUARDDUTY] + SEVERITY_FILTERED_PRODUCTS:
        for severity in OCSF_SEVERITY_IDS:
            for account_id in [INCLUDED] + excluded_accounts:
                expected = account_id not in excluded_accounts and (
                    product == GUARDDUTY or severity in forwarded_severities
                )
                event = finding_event(severity, account_id=account_id, product=product)
                result = events_client.test_event_pattern(
                    EventPattern=rule["event_pattern"], Event=json.dumps(event)
                )["Result"]
                LOG.info(
                    "%s finding, %s, of account %s: %s",
                    product,
                    severity,
                    account_id,
                    "forwarded" if result else "dropped",
                )
                if result is not expected:
                    mismatches.append((product, severity, account_id, result))
    assert mismatches == []
