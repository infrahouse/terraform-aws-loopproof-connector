"""
Settings that change, as a tenant changes them by pull request: LoopProof's defaults, then a target changed, then
the input left out again. Each apply updates the parameter in place, as a new SSM version, which is what LoopProof
numbers a new version of the settings by, and touches nothing else. One test, so that the steps run in order.
"""

from typing import Any, Dict, List, Optional, Tuple

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    DEFAULT_TENANT_SETTINGS,
    DEFAULT_TENANT_SETTINGS_JSON,
    TENANT_SETTINGS_PARAMETER,
    THREAT_KIND,
    connector_applied,
    connector_tfvars,
    new_external_id,
    new_registration_token,
    terraform,
    terraform_check,
    terraform_json,
    write_terraform_tf,
    write_tfvars,
)

# A tenant whose policy gives a High threat 10 days, not LoopProof's 14.
HIGH_THREATS_IN_TEN_DAYS = {"sla_target_days": {THREAT_KIND: {"high": 10}}}


def published(ssm_client: Any) -> Dict[str, Any]:
    """
    :param ssm_client: Systems Manager in the tenant's Region.
    :return: The parameter, as GetParameter returns it.
    """
    return ssm_client.get_parameter(Name=TENANT_SETTINGS_PARAMETER)["Parameter"]


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_settings_change_takes_effect_on_next_apply(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    ssm_client,
    registration_server,
):
    """
    Changing a target updates the parameter in place, as its next version, with every other setting as it was;
    leaving the input out again publishes the defaults' bytes, as the version after. Each takes one apply,
    which touches nothing else, and the plan after is empty.
    """
    tfvars: Dict[str, Any] = connector_tfvars(
        aws_region, test_role_arn, registration_server.url
    )
    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(CONNECTOR_ROOT, tfvars)

    changed = {
        **DEFAULT_TENANT_SETTINGS,
        "sla_target_days": {
            **DEFAULT_TENANT_SETTINGS["sla_target_days"],
            THREAT_KIND: {
                **DEFAULT_TENANT_SETTINGS["sla_target_days"][THREAT_KIND],
                "high": 10,
            },
        },
    }
    with connector_applied(
        CONNECTOR_ROOT,
        ssm_client,
        [new_external_id()],
        new_registration_token(),
        destroy_after=not keep_after,
    ):
        parameter = published(ssm_client)
        assert parameter["Value"] == DEFAULT_TENANT_SETTINGS_JSON
        assert parameter["Version"] == 1

        steps: List[Tuple[Optional[Dict[str, Any]], str, int]] = [
            (HIGH_THREATS_IN_TEN_DAYS, terraform_json(changed), 2),
            (None, DEFAULT_TENANT_SETTINGS_JSON, 3),
        ]
        for settings, value, version in steps:
            write_tfvars(CONNECTOR_ROOT, {**tfvars, "tenant_settings": settings})
            log = terraform_check(
                CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve"
            )
            # The parameter's value, and nothing else.
            assert "Resources: 0 added, 1 changed, 0 destroyed." in log
            assert "module.connector.aws_ssm_parameter.tenant_settings" in log
            parameter = published(ssm_client)
            assert parameter["Value"] == value
            assert parameter["Version"] == version

        result = terraform(CONNECTOR_ROOT, "plan", "-input=false", "-detailed-exitcode")
        assert result.returncode == 0, "the plan after the last apply isn't empty"
        # The settings' changes don't touch the role, so the connector registered once.
        assert len(registration_server.requests) == 1
